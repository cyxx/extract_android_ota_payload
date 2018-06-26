# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verifying the integrity of a Chrome OS update payload.

This module is used internally by the main Payload class for verifying the
integrity of an update payload. The interface for invoking the checks is as
follows:

  checker = PayloadChecker(payload)
  checker.Run(...)
"""

from __future__ import print_function

import array
import base64
import hashlib
import itertools
import os
import subprocess

import common
import error
import format_utils
import histogram
import update_metadata_pb2


#
# Constants.
#

_CHECK_DST_PSEUDO_EXTENTS = 'dst-pseudo-extents'
_CHECK_MOVE_SAME_SRC_DST_BLOCK = 'move-same-src-dst-block'
_CHECK_PAYLOAD_SIG = 'payload-sig'
CHECKS_TO_DISABLE = (
    _CHECK_DST_PSEUDO_EXTENTS,
    _CHECK_MOVE_SAME_SRC_DST_BLOCK,
    _CHECK_PAYLOAD_SIG,
)

_TYPE_FULL = 'full'
_TYPE_DELTA = 'delta'

_DEFAULT_BLOCK_SIZE = 4096

_DEFAULT_PUBKEY_BASE_NAME = 'update-payload-key.pub.pem'
_DEFAULT_PUBKEY_FILE_NAME = os.path.join(os.path.dirname(__file__),
                                         _DEFAULT_PUBKEY_BASE_NAME)

# Supported minor version map to payload types allowed to be using them.
_SUPPORTED_MINOR_VERSIONS = {
    0: (_TYPE_FULL,),
    1: (_TYPE_DELTA,),
    2: (_TYPE_DELTA,),
    3: (_TYPE_DELTA,),
    4: (_TYPE_DELTA,),
}

_OLD_DELTA_USABLE_PART_SIZE = 2 * 1024 * 1024 * 1024

#
# Helper functions.
#

def _IsPowerOfTwo(val):
  """Returns True iff val is a power of two."""
  return val > 0 and (val & (val - 1)) == 0


def _AddFormat(format_func, value):
  """Adds a custom formatted representation to ordinary string representation.

  Args:
    format_func: A value formatter.
    value: Value to be formatted and returned.

  Returns:
    A string 'x (y)' where x = str(value) and y = format_func(value).
  """
  ret = str(value)
  formatted_str = format_func(value)
  if formatted_str:
    ret += ' (%s)' % formatted_str
  return ret


def _AddHumanReadableSize(size):
  """Adds a human readable representation to a byte size value."""
  return _AddFormat(format_utils.BytesToHumanReadable, size)


#
# Payload report generator.
#

class _PayloadReport(object):
  """A payload report generator.

  A report is essentially a sequence of nodes, which represent data points. It
  is initialized to have a "global", untitled section. A node may be a
  sub-report itself.
  """

  # Report nodes: Field, sub-report, section.
  class Node(object):
    """A report node interface."""

    @staticmethod
    def _Indent(indent, line):
      """Indents a line by a given indentation amount.

      Args:
        indent: The indentation amount.
        line: The line content (string).

      Returns:
        The properly indented line (string).
      """
      return '%*s%s' % (indent, '', line)

    def GenerateLines(self, base_indent, sub_indent, curr_section):
      """Generates the report lines for this node.

      Args:
        base_indent: Base indentation for each line.
        sub_indent: Additional indentation for sub-nodes.
        curr_section: The current report section object.

      Returns:
        A pair consisting of a list of properly indented report lines and a new
        current section object.
      """
      raise NotImplementedError

  class FieldNode(Node):
    """A field report node, representing a (name, value) pair."""

    def __init__(self, name, value, linebreak, indent):
      super(_PayloadReport.FieldNode, self).__init__()
      self.name = name
      self.value = value
      self.linebreak = linebreak
      self.indent = indent

    def GenerateLines(self, base_indent, sub_indent, curr_section):
      """Generates a properly formatted 'name : value' entry."""
      report_output = ''
      if self.name:
        report_output += self.name.ljust(curr_section.max_field_name_len) + ' :'
      value_lines = str(self.value).splitlines()
      if self.linebreak and self.name:
        report_output += '\n' + '\n'.join(
            ['%*s%s' % (self.indent, '', line) for line in value_lines])
      else:
        if self.name:
          report_output += ' '
        report_output += '%*s' % (self.indent, '')
        cont_line_indent = len(report_output)
        indented_value_lines = [value_lines[0]]
        indented_value_lines.extend(['%*s%s' % (cont_line_indent, '', line)
                                     for line in value_lines[1:]])
        report_output += '\n'.join(indented_value_lines)

      report_lines = [self._Indent(base_indent, line + '\n')
                      for line in report_output.split('\n')]
      return report_lines, curr_section

  class SubReportNode(Node):
    """A sub-report node, representing a nested report."""

    def __init__(self, title, report):
      super(_PayloadReport.SubReportNode, self).__init__()
      self.title = title
      self.report = report

    def GenerateLines(self, base_indent, sub_indent, curr_section):
      """Recurse with indentation."""
      report_lines = [self._Indent(base_indent, self.title + ' =>\n')]
      report_lines.extend(self.report.GenerateLines(base_indent + sub_indent,
                                                    sub_indent))
      return report_lines, curr_section

  class SectionNode(Node):
    """A section header node."""

    def __init__(self, title=None):
      super(_PayloadReport.SectionNode, self).__init__()
      self.title = title
      self.max_field_name_len = 0

    def GenerateLines(self, base_indent, sub_indent, curr_section):
      """Dump a title line, return self as the (new) current section."""
      report_lines = []
      if self.title:
        report_lines.append(self._Indent(base_indent,
                                         '=== %s ===\n' % self.title))
      return report_lines, self

  def __init__(self):
    self.report = []
    self.last_section = self.global_section = self.SectionNode()
    self.is_finalized = False

  def GenerateLines(self, base_indent, sub_indent):
    """Generates the lines in the report, properly indented.

    Args:
      base_indent: The indentation used for root-level report lines.
      sub_indent: The indentation offset used for sub-reports.

    Returns:
      A list of indented report lines.
    """
    report_lines = []
    curr_section = self.global_section
    for node in self.report:
      node_report_lines, curr_section = node.GenerateLines(
          base_indent, sub_indent, curr_section)
      report_lines.extend(node_report_lines)

    return report_lines

  def Dump(self, out_file, base_indent=0, sub_indent=2):
    """Dumps the report to a file.

    Args:
      out_file: File object to output the content to.
      base_indent: Base indentation for report lines.
      sub_indent: Added indentation for sub-reports.
    """
    report_lines = self.GenerateLines(base_indent, sub_indent)
    if report_lines and not self.is_finalized:
      report_lines.append('(incomplete report)\n')

    for line in report_lines:
      out_file.write(line)

  def AddField(self, name, value, linebreak=False, indent=0):
    """Adds a field/value pair to the payload report.

    Args:
      name: The field's name.
      value: The field's value.
      linebreak: Whether the value should be printed on a new line.
      indent: Amount of extra indent for each line of the value.
    """
    assert not self.is_finalized
    if name and self.last_section.max_field_name_len < len(name):
      self.last_section.max_field_name_len = len(name)
    self.report.append(self.FieldNode(name, value, linebreak, indent))

  def AddSubReport(self, title):
    """Adds and returns a sub-report with a title."""
    assert not self.is_finalized
    sub_report = self.SubReportNode(title, type(self)())
    self.report.append(sub_report)
    return sub_report.report

  def AddSection(self, title):
    """Adds a new section title."""
    assert not self.is_finalized
    self.last_section = self.SectionNode(title)
    self.report.append(self.last_section)

  def Finalize(self):
    """Seals the report, marking it as complete."""
    self.is_finalized = True


#
# Payload verification.
#

class PayloadChecker(object):
  """Checking the integrity of an update payload.

  This is a short-lived object whose purpose is to isolate the logic used for
  verifying the integrity of an update payload.
  """

  def __init__(self, payload, assert_type=None, block_size=0,
               allow_unhashed=False, disabled_tests=()):
    """Initialize the checker.

    Args:
      payload: The payload object to check.
      assert_type: Assert that payload is either 'full' or 'delta' (optional).
      block_size: Expected filesystem / payload block size (optional).
      allow_unhashed: Allow operations with unhashed data blobs.
      disabled_tests: Sequence of tests to disable.
    """
    if not payload.is_init:
      raise ValueError('Uninitialized update payload.')

    # Set checker configuration.
    self.payload = payload
    self.block_size = block_size if block_size else _DEFAULT_BLOCK_SIZE
    if not _IsPowerOfTwo(self.block_size):
      raise error.PayloadError(
          'Expected block (%d) size is not a power of two.' % self.block_size)
    if assert_type not in (None, _TYPE_FULL, _TYPE_DELTA):
      raise error.PayloadError('Invalid assert_type value (%r).' %
                               assert_type)
    self.payload_type = assert_type
    self.allow_unhashed = allow_unhashed

    # Disable specific tests.
    self.check_dst_pseudo_extents = (
        _CHECK_DST_PSEUDO_EXTENTS not in disabled_tests)
    self.check_move_same_src_dst_block = (
        _CHECK_MOVE_SAME_SRC_DST_BLOCK not in disabled_tests)
    self.check_payload_sig = _CHECK_PAYLOAD_SIG not in disabled_tests

    # Reset state; these will be assigned when the manifest is checked.
    self.sigs_offset = 0
    self.sigs_size = 0
    self.old_rootfs_fs_size = 0
    self.old_kernel_fs_size = 0
    self.new_rootfs_fs_size = 0
    self.new_kernel_fs_size = 0
    self.minor_version = None

  @staticmethod
  def _CheckElem(msg, name, report, is_mandatory, is_submsg, convert=str,
                 msg_name=None, linebreak=False, indent=0):
    """Adds an element from a protobuf message to the payload report.

    Checks to see whether a message contains a given element, and if so adds
    the element value to the provided report. A missing mandatory element
    causes an exception to be raised.

    Args:
      msg: The message containing the element.
      name: The name of the element.
      report: A report object to add the element name/value to.
      is_mandatory: Whether or not this element must be present.
      is_submsg: Whether this element is itself a message.
      convert: A function for converting the element value for reporting.
      msg_name: The name of the message object (for error reporting).
      linebreak: Whether the value report should induce a line break.
      indent: Amount of indent used for reporting the value.

    Returns:
      A pair consisting of the element value and the generated sub-report for
      it (if the element is a sub-message, None otherwise). If the element is
      missing, returns (None, None).

    Raises:
      error.PayloadError if a mandatory element is missing.
    """
    if not msg.HasField(name):
      if is_mandatory:
        raise error.PayloadError('%smissing mandatory %s %r.' %
                                 (msg_name + ' ' if msg_name else '',
                                  'sub-message' if is_submsg else 'field',
                                  name))
      return None, None

    value = getattr(msg, name)
    if is_submsg:
      return value, report and report.AddSubReport(name)
    else:
      if report:
        report.AddField(name, convert(value), linebreak=linebreak,
                        indent=indent)
      return value, None

  @staticmethod
  def _CheckMandatoryField(msg, field_name, report, msg_name, convert=str,
                           linebreak=False, indent=0):
    """Adds a mandatory field; returning first component from _CheckElem."""
    return PayloadChecker._CheckElem(msg, field_name, report, True, False,
                                     convert=convert, msg_name=msg_name,
                                     linebreak=linebreak, indent=indent)[0]

  @staticmethod
  def _CheckOptionalField(msg, field_name, report, convert=str,
                          linebreak=False, indent=0):
    """Adds an optional field; returning first component from _CheckElem."""
    return PayloadChecker._CheckElem(msg, field_name, report, False, False,
                                     convert=convert, linebreak=linebreak,
                                     indent=indent)[0]

  @staticmethod
  def _CheckMandatorySubMsg(msg, submsg_name, report, msg_name):
    """Adds a mandatory sub-message; wrapper for _CheckElem."""
    return PayloadChecker._CheckElem(msg, submsg_name, report, True, True,
                                     msg_name)

  @staticmethod
  def _CheckOptionalSubMsg(msg, submsg_name, report):
    """Adds an optional sub-message; wrapper for _CheckElem."""
    return PayloadChecker._CheckElem(msg, submsg_name, report, False, True)

  @staticmethod
  def _CheckPresentIff(val1, val2, name1, name2, obj_name):
    """Checks that val1 is None iff val2 is None.

    Args:
      val1: first value to be compared.
      val2: second value to be compared.
      name1: name of object holding the first value.
      name2: name of object holding the second value.
      obj_name: Name of the object containing these values.

    Raises:
      error.PayloadError if assertion does not hold.
    """
    if None in (val1, val2) and val1 is not val2:
      present, missing = (name1, name2) if val2 is None else (name2, name1)
      raise error.PayloadError('%r present without %r%s.' %
                               (present, missing,
                                ' in ' + obj_name if obj_name else ''))

  @staticmethod
  def _Run(cmd, send_data=None):
    """Runs a subprocess, returns its output.

    Args:
      cmd: Sequence of command-line argument for invoking the subprocess.
      send_data: Data to feed to the process via its stdin.

    Returns:
      A tuple containing the stdout and stderr output of the process.
    """
    run_process = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE)
    try:
      result = run_process.communicate(input=send_data)
    finally:
      exit_code = run_process.wait()

    if exit_code:
      raise RuntimeError('Subprocess %r failed with code %r.' %
                         (cmd, exit_code))

    return result

  @staticmethod
  def _CheckSha256Signature(sig_data, pubkey_file_name, actual_hash, sig_name):
    """Verifies an actual hash against a signed one.

    Args:
      sig_data: The raw signature data.
      pubkey_file_name: Public key used for verifying signature.
      actual_hash: The actual hash digest.
      sig_name: Signature name for error reporting.

    Raises:
      error.PayloadError if signature could not be verified.
    """
    if len(sig_data) != 256:
      raise error.PayloadError(
          '%s: signature size (%d) not as expected (256).' %
          (sig_name, len(sig_data)))
    signed_data, _ = PayloadChecker._Run(
        ['openssl', 'rsautl', '-verify', '-pubin', '-inkey', pubkey_file_name],
        send_data=sig_data)

    if len(signed_data) != len(common.SIG_ASN1_HEADER) + 32:
      raise error.PayloadError('%s: unexpected signed data length (%d).' %
                               (sig_name, len(signed_data)))

    if not signed_data.startswith(common.SIG_ASN1_HEADER):
      raise error.PayloadError('%s: not containing standard ASN.1 prefix.' %
                               sig_name)

    signed_hash = signed_data[len(common.SIG_ASN1_HEADER):]
    if signed_hash != actual_hash:
      raise error.PayloadError(
          '%s: signed hash (%s) different from actual (%s).' %
          (sig_name, common.FormatSha256(signed_hash),
           common.FormatSha256(actual_hash)))

  @staticmethod
  def _CheckBlocksFitLength(length, num_blocks, block_size, length_name,
                            block_name=None):
    """Checks that a given length fits given block space.

    This ensures that the number of blocks allocated is appropriate for the
    length of the data residing in these blocks.

    Args:
      length: The actual length of the data.
      num_blocks: The number of blocks allocated for it.
      block_size: The size of each block in bytes.
      length_name: Name of length (used for error reporting).
      block_name: Name of block (used for error reporting).

    Raises:
      error.PayloadError if the aforementioned invariant is not satisfied.
    """
    # Check: length <= num_blocks * block_size.
    if length > num_blocks * block_size:
      raise error.PayloadError(
          '%s (%d) > num %sblocks (%d) * block_size (%d).' %
          (length_name, length, block_name or '', num_blocks, block_size))

    # Check: length > (num_blocks - 1) * block_size.
    if length <= (num_blocks - 1) * block_size:
      raise error.PayloadError(
          '%s (%d) <= (num %sblocks - 1 (%d)) * block_size (%d).' %
          (length_name, length, block_name or '', num_blocks - 1, block_size))

  def _CheckManifestMinorVersion(self, report):
    """Checks the payload manifest minor_version field.

    Args:
      report: The report object to add to.

    Raises:
      error.PayloadError if any of the checks fail.
    """
    self.minor_version = self._CheckOptionalField(self.payload.manifest,
                                                  'minor_version', report)
    if self.minor_version in _SUPPORTED_MINOR_VERSIONS:
      if self.payload_type not in _SUPPORTED_MINOR_VERSIONS[self.minor_version]:
        raise error.PayloadError(
            'Minor version %d not compatible with payload type %s.' %
            (self.minor_version, self.payload_type))
    elif self.minor_version is None:
      raise error.PayloadError('Minor version is not set.')
    else:
      raise error.PayloadError('Unsupported minor version: %d' %
                               self.minor_version)

  def _CheckManifest(self, report, rootfs_part_size=0, kernel_part_size=0):
    """Checks the payload manifest.

    Args:
      report: A report object to add to.
      rootfs_part_size: Size of the rootfs partition in bytes.
      kernel_part_size: Size of the kernel partition in bytes.

    Returns:
      A tuple consisting of the partition block size used during the update
      (integer), the signatures block offset and size.

    Raises:
      error.PayloadError if any of the checks fail.
    """
    manifest = self.payload.manifest
    report.AddSection('manifest')

    # Check: block_size must exist and match the expected value.
    actual_block_size = self._CheckMandatoryField(manifest, 'block_size',
                                                  report, 'manifest')
    if actual_block_size != self.block_size:
      raise error.PayloadError('Block_size (%d) not as expected (%d).' %
                               (actual_block_size, self.block_size))

    # Check: signatures_offset <==> signatures_size.
    self.sigs_offset = self._CheckOptionalField(manifest, 'signatures_offset',
                                                report)
    self.sigs_size = self._CheckOptionalField(manifest, 'signatures_size',
                                              report)
    self._CheckPresentIff(self.sigs_offset, self.sigs_size,
                          'signatures_offset', 'signatures_size', 'manifest')

    # Check: old_kernel_info <==> old_rootfs_info.
    oki_msg, oki_report = self._CheckOptionalSubMsg(manifest,
                                                    'old_kernel_info', report)
    ori_msg, ori_report = self._CheckOptionalSubMsg(manifest,
                                                    'old_rootfs_info', report)
    self._CheckPresentIff(oki_msg, ori_msg, 'old_kernel_info',
                          'old_rootfs_info', 'manifest')
    if oki_msg:  # equivalently, ori_msg
      # Assert/mark delta payload.
      if self.payload_type == _TYPE_FULL:
        raise error.PayloadError(
            'Apparent full payload contains old_{kernel,rootfs}_info.')
      self.payload_type = _TYPE_DELTA

      # Check: {size, hash} present in old_{kernel,rootfs}_info.
      self.old_kernel_fs_size = self._CheckMandatoryField(
          oki_msg, 'size', oki_report, 'old_kernel_info')
      self._CheckMandatoryField(oki_msg, 'hash', oki_report, 'old_kernel_info',
                                convert=common.FormatSha256)
      self.old_rootfs_fs_size = self._CheckMandatoryField(
          ori_msg, 'size', ori_report, 'old_rootfs_info')
      self._CheckMandatoryField(ori_msg, 'hash', ori_report, 'old_rootfs_info',
                                convert=common.FormatSha256)

      # Check: old_{kernel,rootfs} size must fit in respective partition.
      if kernel_part_size and self.old_kernel_fs_size > kernel_part_size:
        raise error.PayloadError(
            'Old kernel content (%d) exceed partition size (%d).' %
            (self.old_kernel_fs_size, kernel_part_size))
      if rootfs_part_size and self.old_rootfs_fs_size > rootfs_part_size:
        raise error.PayloadError(
            'Old rootfs content (%d) exceed partition size (%d).' %
            (self.old_rootfs_fs_size, rootfs_part_size))
    else:
      # Assert/mark full payload.
      if self.payload_type == _TYPE_DELTA:
        raise error.PayloadError(
            'Apparent delta payload missing old_{kernel,rootfs}_info.')
      self.payload_type = _TYPE_FULL

    # Check: new_kernel_info present; contains {size, hash}.
    nki_msg, nki_report = self._CheckMandatorySubMsg(
        manifest, 'new_kernel_info', report, 'manifest')
    self.new_kernel_fs_size = self._CheckMandatoryField(
        nki_msg, 'size', nki_report, 'new_kernel_info')
    self._CheckMandatoryField(nki_msg, 'hash', nki_report, 'new_kernel_info',
                              convert=common.FormatSha256)

    # Check: new_rootfs_info present; contains {size, hash}.
    nri_msg, nri_report = self._CheckMandatorySubMsg(
        manifest, 'new_rootfs_info', report, 'manifest')
    self.new_rootfs_fs_size = self._CheckMandatoryField(
        nri_msg, 'size', nri_report, 'new_rootfs_info')
    self._CheckMandatoryField(nri_msg, 'hash', nri_report, 'new_rootfs_info',
                              convert=common.FormatSha256)

    # Check: new_{kernel,rootfs} size must fit in respective partition.
    if kernel_part_size and self.new_kernel_fs_size > kernel_part_size:
      raise error.PayloadError(
          'New kernel content (%d) exceed partition size (%d).' %
          (self.new_kernel_fs_size, kernel_part_size))
    if rootfs_part_size and self.new_rootfs_fs_size > rootfs_part_size:
      raise error.PayloadError(
          'New rootfs content (%d) exceed partition size (%d).' %
          (self.new_rootfs_fs_size, rootfs_part_size))

    # Check: minor_version makes sense for the payload type. This check should
    # run after the payload type has been set.
    self._CheckManifestMinorVersion(report)

  def _CheckLength(self, length, total_blocks, op_name, length_name):
    """Checks whether a length matches the space designated in extents.

    Args:
      length: The total length of the data.
      total_blocks: The total number of blocks in extents.
      op_name: Operation name (for error reporting).
      length_name: Length name (for error reporting).

    Raises:
      error.PayloadError is there a problem with the length.
    """
    # Check: length is non-zero.
    if length == 0:
      raise error.PayloadError('%s: %s is zero.' % (op_name, length_name))

    # Check that length matches number of blocks.
    self._CheckBlocksFitLength(length, total_blocks, self.block_size,
                               '%s: %s' % (op_name, length_name))

  def _CheckExtents(self, extents, usable_size, block_counters, name,
                    allow_pseudo=False, allow_signature=False):
    """Checks a sequence of extents.

    Args:
      extents: The sequence of extents to check.
      usable_size: The usable size of the partition to which the extents apply.
      block_counters: Array of counters corresponding to the number of blocks.
      name: The name of the extent block.
      allow_pseudo: Whether or not pseudo block numbers are allowed.
      allow_signature: Whether or not the extents are used for a signature.

    Returns:
      The total number of blocks in the extents.

    Raises:
      error.PayloadError if any of the entailed checks fails.
    """
    total_num_blocks = 0
    for ex, ex_name in common.ExtentIter(extents, name):
      # Check: Mandatory fields.
      start_block = PayloadChecker._CheckMandatoryField(ex, 'start_block',
                                                        None, ex_name)
      num_blocks = PayloadChecker._CheckMandatoryField(ex, 'num_blocks', None,
                                                       ex_name)
      end_block = start_block + num_blocks

      # Check: num_blocks > 0.
      if num_blocks == 0:
        raise error.PayloadError('%s: extent length is zero.' % ex_name)

      if start_block != common.PSEUDO_EXTENT_MARKER:
        # Check: Make sure we're within the partition limit.
        if usable_size and end_block * self.block_size > usable_size:
          raise error.PayloadError(
              '%s: extent (%s) exceeds usable partition size (%d).' %
              (ex_name, common.FormatExtent(ex, self.block_size), usable_size))

        # Record block usage.
        for i in xrange(start_block, end_block):
          block_counters[i] += 1
      elif not (allow_pseudo or (allow_signature and len(extents) == 1)):
        # Pseudo-extents must be allowed explicitly, or otherwise be part of a
        # signature operation (in which case there has to be exactly one).
        raise error.PayloadError('%s: unexpected pseudo-extent.' % ex_name)

      total_num_blocks += num_blocks

    return total_num_blocks

  def _CheckReplaceOperation(self, op, data_length, total_dst_blocks, op_name):
    """Specific checks for REPLACE/REPLACE_BZ operations.

    Args:
      op: The operation object from the manifest.
      data_length: The length of the data blob associated with the operation.
      total_dst_blocks: Total number of blocks in dst_extents.
      op_name: Operation name for error reporting.

    Raises:
      error.PayloadError if any check fails.
    """
    # Check: Does not contain src extents.
    if op.src_extents:
      raise error.PayloadError('%s: contains src_extents.' % op_name)

    # Check: Contains data.
    if data_length is None:
      raise error.PayloadError('%s: missing data_{offset,length}.' % op_name)

    if op.type == common.OpType.REPLACE:
      PayloadChecker._CheckBlocksFitLength(data_length, total_dst_blocks,
                                           self.block_size,
                                           op_name + '.data_length', 'dst')
    else:
      # Check: data_length must be smaller than the alotted dst blocks.
      if data_length >= total_dst_blocks * self.block_size:
        raise error.PayloadError(
            '%s: data_length (%d) must be less than allotted dst block '
            'space (%d * %d).' %
            (op_name, data_length, total_dst_blocks, self.block_size))

  def _CheckMoveOperation(self, op, data_offset, total_src_blocks,
                          total_dst_blocks, op_name):
    """Specific checks for MOVE operations.

    Args:
      op: The operation object from the manifest.
      data_offset: The offset of a data blob for the operation.
      total_src_blocks: Total number of blocks in src_extents.
      total_dst_blocks: Total number of blocks in dst_extents.
      op_name: Operation name for error reporting.

    Raises:
      error.PayloadError if any check fails.
    """
    # Check: No data_{offset,length}.
    if data_offset is not None:
      raise error.PayloadError('%s: contains data_{offset,length}.' % op_name)

    # Check: total_src_blocks == total_dst_blocks.
    if total_src_blocks != total_dst_blocks:
      raise error.PayloadError(
          '%s: total src blocks (%d) != total dst blocks (%d).' %
          (op_name, total_src_blocks, total_dst_blocks))

    # Check: For all i, i-th src block index != i-th dst block index.
    i = 0
    src_extent_iter = iter(op.src_extents)
    dst_extent_iter = iter(op.dst_extents)
    src_extent = dst_extent = None
    src_idx = src_num = dst_idx = dst_num = 0
    while i < total_src_blocks:
      # Get the next source extent, if needed.
      if not src_extent:
        try:
          src_extent = src_extent_iter.next()
        except StopIteration:
          raise error.PayloadError('%s: ran out of src extents (%d/%d).' %
                                   (op_name, i, total_src_blocks))
        src_idx = src_extent.start_block
        src_num = src_extent.num_blocks

      # Get the next dest extent, if needed.
      if not dst_extent:
        try:
          dst_extent = dst_extent_iter.next()
        except StopIteration:
          raise error.PayloadError('%s: ran out of dst extents (%d/%d).' %
                                   (op_name, i, total_dst_blocks))
        dst_idx = dst_extent.start_block
        dst_num = dst_extent.num_blocks

      # Check: start block is not 0. See crbug/480751; there are still versions
      # of update_engine which fail when seeking to 0 in PReadAll and PWriteAll,
      # so we need to fail payloads that try to MOVE to/from block 0.
      if src_idx == 0 or dst_idx == 0:
        raise error.PayloadError(
            '%s: MOVE operation cannot have extent with start block 0' %
            op_name)

      if self.check_move_same_src_dst_block and src_idx == dst_idx:
        raise error.PayloadError(
            '%s: src/dst block number %d is the same (%d).' %
            (op_name, i, src_idx))

      advance = min(src_num, dst_num)
      i += advance

      src_idx += advance
      src_num -= advance
      if src_num == 0:
        src_extent = None

      dst_idx += advance
      dst_num -= advance
      if dst_num == 0:
        dst_extent = None

    # Make sure we've exhausted all src/dst extents.
    if src_extent:
      raise error.PayloadError('%s: excess src blocks.' % op_name)
    if dst_extent:
      raise error.PayloadError('%s: excess dst blocks.' % op_name)

  def _CheckAnyDiffOperation(self, data_length, total_dst_blocks, op_name):
    """Specific checks for BSDIFF, SOURCE_BSDIFF and IMGDIFF operations.

    Args:
      data_length: The length of the data blob associated with the operation.
      total_dst_blocks: Total number of blocks in dst_extents.
      op_name: Operation name for error reporting.

    Raises:
      error.PayloadError if any check fails.
    """
    # Check: data_{offset,length} present.
    if data_length is None:
      raise error.PayloadError('%s: missing data_{offset,length}.' % op_name)

    # Check: data_length is strictly smaller than the alotted dst blocks.
    if data_length >= total_dst_blocks * self.block_size:
      raise error.PayloadError(
          '%s: data_length (%d) must be smaller than allotted dst space '
          '(%d * %d = %d).' %
          (op_name, data_length, total_dst_blocks, self.block_size,
           total_dst_blocks * self.block_size))

  def _CheckSourceCopyOperation(self, data_offset, total_src_blocks,
                                total_dst_blocks, op_name):
    """Specific checks for SOURCE_COPY.

    Args:
      data_offset: The offset of a data blob for the operation.
      total_src_blocks: Total number of blocks in src_extents.
      total_dst_blocks: Total number of blocks in dst_extents.
      op_name: Operation name for error reporting.

    Raises:
      error.PayloadError if any check fails.
    """
    # Check: No data_{offset,length}.
    if data_offset is not None:
      raise error.PayloadError('%s: contains data_{offset,length}.' % op_name)

    # Check: total_src_blocks == total_dst_blocks.
    if total_src_blocks != total_dst_blocks:
      raise error.PayloadError(
          '%s: total src blocks (%d) != total dst blocks (%d).' %
          (op_name, total_src_blocks, total_dst_blocks))

  def _CheckAnySourceOperation(self, op, total_src_blocks, op_name):
    """Specific checks for SOURCE_* operations.

    Args:
      op: The operation object from the manifest.
      total_src_blocks: Total number of blocks in src_extents.
      op_name: Operation name for error reporting.

    Raises:
      error.PayloadError if any check fails.
    """
    # Check: total_src_blocks != 0.
    if total_src_blocks == 0:
      raise error.PayloadError('%s: no src blocks in a source op.' % op_name)

    # Check: src_sha256_hash present in minor version >= 3.
    if self.minor_version >= 3 and op.src_sha256_hash is None:
      raise error.PayloadError('%s: source hash missing.' % op_name)

  def _CheckOperation(self, op, op_name, is_last, old_block_counters,
                      new_block_counters, old_usable_size, new_usable_size,
                      prev_data_offset, allow_signature, blob_hash_counts):
    """Checks a single update operation.

    Args:
      op: The operation object.
      op_name: Operation name string for error reporting.
      is_last: Whether this is the last operation in the sequence.
      old_block_counters: Arrays of block read counters.
      new_block_counters: Arrays of block write counters.
      old_usable_size: The overall usable size for src data in bytes.
      new_usable_size: The overall usable size for dst data in bytes.
      prev_data_offset: Offset of last used data bytes.
      allow_signature: Whether this may be a signature operation.
      blob_hash_counts: Counters for hashed/unhashed blobs.

    Returns:
      The amount of data blob associated with the operation.

    Raises:
      error.PayloadError if any check has failed.
    """
    # Check extents.
    total_src_blocks = self._CheckExtents(
        op.src_extents, old_usable_size, old_block_counters,
        op_name + '.src_extents', allow_pseudo=True)
    allow_signature_in_extents = (allow_signature and is_last and
                                  op.type == common.OpType.REPLACE)
    total_dst_blocks = self._CheckExtents(
        op.dst_extents, new_usable_size, new_block_counters,
        op_name + '.dst_extents',
        allow_pseudo=(not self.check_dst_pseudo_extents),
        allow_signature=allow_signature_in_extents)

    # Check: data_offset present <==> data_length present.
    data_offset = self._CheckOptionalField(op, 'data_offset', None)
    data_length = self._CheckOptionalField(op, 'data_length', None)
    self._CheckPresentIff(data_offset, data_length, 'data_offset',
                          'data_length', op_name)

    # Check: At least one dst_extent.
    if not op.dst_extents:
      raise error.PayloadError('%s: dst_extents is empty.' % op_name)

    # Check {src,dst}_length, if present.
    if op.HasField('src_length'):
      self._CheckLength(op.src_length, total_src_blocks, op_name, 'src_length')
    if op.HasField('dst_length'):
      self._CheckLength(op.dst_length, total_dst_blocks, op_name, 'dst_length')

    if op.HasField('data_sha256_hash'):
      blob_hash_counts['hashed'] += 1

      # Check: Operation carries data.
      if data_offset is None:
        raise error.PayloadError(
            '%s: data_sha256_hash present but no data_{offset,length}.' %
            op_name)

      # Check: Hash verifies correctly.
      # pylint cannot find the method in hashlib, for some reason.
      # pylint: disable=E1101
      actual_hash = hashlib.sha256(self.payload.ReadDataBlob(data_offset,
                                                             data_length))
      if op.data_sha256_hash != actual_hash.digest():
        raise error.PayloadError(
            '%s: data_sha256_hash (%s) does not match actual hash (%s).' %
            (op_name, common.FormatSha256(op.data_sha256_hash),
             common.FormatSha256(actual_hash.digest())))
    elif data_offset is not None:
      if allow_signature_in_extents:
        blob_hash_counts['signature'] += 1
      elif self.allow_unhashed:
        blob_hash_counts['unhashed'] += 1
      else:
        raise error.PayloadError('%s: unhashed operation not allowed.' %
                                 op_name)

    if data_offset is not None:
      # Check: Contiguous use of data section.
      if data_offset != prev_data_offset:
        raise error.PayloadError(
            '%s: data offset (%d) not matching amount used so far (%d).' %
            (op_name, data_offset, prev_data_offset))

    # Type-specific checks.
    if op.type in (common.OpType.REPLACE, common.OpType.REPLACE_BZ):
      self._CheckReplaceOperation(op, data_length, total_dst_blocks, op_name)
    elif op.type == common.OpType.MOVE and self.minor_version == 1:
      self._CheckMoveOperation(op, data_offset, total_src_blocks,
                               total_dst_blocks, op_name)
    elif op.type == common.OpType.BSDIFF and self.minor_version == 1:
      self._CheckAnyDiffOperation(data_length, total_dst_blocks, op_name)
    elif op.type == common.OpType.SOURCE_COPY and self.minor_version >= 2:
      self._CheckSourceCopyOperation(data_offset, total_src_blocks,
                                     total_dst_blocks, op_name)
      self._CheckAnySourceOperation(op, total_src_blocks, op_name)
    elif op.type == common.OpType.SOURCE_BSDIFF and self.minor_version >= 2:
      self._CheckAnyDiffOperation(data_length, total_dst_blocks, op_name)
      self._CheckAnySourceOperation(op, total_src_blocks, op_name)
    elif op.type == common.OpType.IMGDIFF and self.minor_version >= 4:
      self._CheckAnyDiffOperation(data_length, total_dst_blocks, op_name)
      self._CheckAnySourceOperation(op, total_src_blocks, op_name)
    else:
      raise error.PayloadError(
          'Operation %s (type %d) not allowed in minor version %d' %
          (op_name, op.type, self.minor_version))
    return data_length if data_length is not None else 0

  def _SizeToNumBlocks(self, size):
    """Returns the number of blocks needed to contain a given byte size."""
    return (size + self.block_size - 1) / self.block_size

  def _AllocBlockCounters(self, total_size):
    """Returns a freshly initialized array of block counters.

    Note that the generated array is not portable as is due to byte-ordering
    issues, hence it should not be serialized.

    Args:
      total_size: The total block size in bytes.

    Returns:
      An array of unsigned short elements initialized to zero, one for each of
      the blocks necessary for containing the partition.
    """
    return array.array('H',
                       itertools.repeat(0, self._SizeToNumBlocks(total_size)))

  def _CheckOperations(self, operations, report, base_name, old_fs_size,
                       new_fs_size, new_usable_size, prev_data_offset,
                       allow_signature):
    """Checks a sequence of update operations.

    Args:
      operations: The sequence of operations to check.
      report: The report object to add to.
      base_name: The name of the operation block.
      old_fs_size: The old filesystem size in bytes.
      new_fs_size: The new filesystem size in bytes.
      new_usable_size: The overall usable size of the new partition in bytes.
      prev_data_offset: Offset of last used data bytes.
      allow_signature: Whether this sequence may contain signature operations.

    Returns:
      The total data blob size used.

    Raises:
      error.PayloadError if any of the checks fails.
    """
    # The total size of data blobs used by operations scanned thus far.
    total_data_used = 0
    # Counts of specific operation types.
    op_counts = {
        common.OpType.REPLACE: 0,
        common.OpType.REPLACE_BZ: 0,
        common.OpType.MOVE: 0,
        common.OpType.BSDIFF: 0,
        common.OpType.SOURCE_COPY: 0,
        common.OpType.SOURCE_BSDIFF: 0,
        common.OpType.IMGDIFF: 0,
    }
    # Total blob sizes for each operation type.
    op_blob_totals = {
        common.OpType.REPLACE: 0,
        common.OpType.REPLACE_BZ: 0,
        # MOVE operations don't have blobs.
        common.OpType.BSDIFF: 0,
        # SOURCE_COPY operations don't have blobs.
        common.OpType.SOURCE_BSDIFF: 0,
        common.OpType.IMGDIFF: 0,
    }
    # Counts of hashed vs unhashed operations.
    blob_hash_counts = {
        'hashed': 0,
        'unhashed': 0,
    }
    if allow_signature:
      blob_hash_counts['signature'] = 0

    # Allocate old and new block counters.
    old_block_counters = (self._AllocBlockCounters(new_usable_size)
                          if old_fs_size else None)
    new_block_counters = self._AllocBlockCounters(new_usable_size)

    # Process and verify each operation.
    op_num = 0
    for op, op_name in common.OperationIter(operations, base_name):
      op_num += 1

      # Check: Type is valid.
      if op.type not in op_counts.keys():
        raise error.PayloadError('%s: invalid type (%d).' % (op_name, op.type))
      op_counts[op.type] += 1

      is_last = op_num == len(operations)
      curr_data_used = self._CheckOperation(
          op, op_name, is_last, old_block_counters, new_block_counters,
          new_usable_size if old_fs_size else 0, new_usable_size,
          prev_data_offset + total_data_used, allow_signature,
          blob_hash_counts)
      if curr_data_used:
        op_blob_totals[op.type] += curr_data_used
        total_data_used += curr_data_used

    # Report totals and breakdown statistics.
    report.AddField('total operations', op_num)
    report.AddField(
        None,
        histogram.Histogram.FromCountDict(op_counts,
                                          key_names=common.OpType.NAMES),
        indent=1)
    report.AddField('total blobs', sum(blob_hash_counts.values()))
    report.AddField(None,
                    histogram.Histogram.FromCountDict(blob_hash_counts),
                    indent=1)
    report.AddField('total blob size', _AddHumanReadableSize(total_data_used))
    report.AddField(
        None,
        histogram.Histogram.FromCountDict(op_blob_totals,
                                          formatter=_AddHumanReadableSize,
                                          key_names=common.OpType.NAMES),
        indent=1)

    # Report read/write histograms.
    if old_block_counters:
      report.AddField('block read hist',
                      histogram.Histogram.FromKeyList(old_block_counters),
                      linebreak=True, indent=1)

    new_write_hist = histogram.Histogram.FromKeyList(
        new_block_counters[:self._SizeToNumBlocks(new_fs_size)])
    report.AddField('block write hist', new_write_hist, linebreak=True,
                    indent=1)

    # Check: Full update must write each dst block once.
    if self.payload_type == _TYPE_FULL and new_write_hist.GetKeys() != [1]:
      raise error.PayloadError(
          '%s: not all blocks written exactly once during full update.' %
          base_name)

    return total_data_used

  def _CheckSignatures(self, report, pubkey_file_name):
    """Checks a payload's signature block."""
    sigs_raw = self.payload.ReadDataBlob(self.sigs_offset, self.sigs_size)
    sigs = update_metadata_pb2.Signatures()
    sigs.ParseFromString(sigs_raw)
    report.AddSection('signatures')

    # Check: At least one signature present.
    # pylint cannot see through the protobuf object, it seems.
    # pylint: disable=E1101
    if not sigs.signatures:
      raise error.PayloadError('Signature block is empty.')

    last_ops_section = (self.payload.manifest.kernel_install_operations or
                        self.payload.manifest.install_operations)
    fake_sig_op = last_ops_section[-1]
    # Check: signatures_{offset,size} must match the last (fake) operation.
    if not (fake_sig_op.type == common.OpType.REPLACE and
            self.sigs_offset == fake_sig_op.data_offset and
            self.sigs_size == fake_sig_op.data_length):
      raise error.PayloadError(
          'Signatures_{offset,size} (%d+%d) does not match last operation '
          '(%d+%d).' %
          (self.sigs_offset, self.sigs_size, fake_sig_op.data_offset,
           fake_sig_op.data_length))

    # Compute the checksum of all data up to signature blob.
    # TODO(garnold) we're re-reading the whole data section into a string
    # just to compute the checksum; instead, we could do it incrementally as
    # we read the blobs one-by-one, under the assumption that we're reading
    # them in order (which currently holds). This should be reconsidered.
    payload_hasher = self.payload.manifest_hasher.copy()
    common.Read(self.payload.payload_file, self.sigs_offset,
                offset=self.payload.data_offset, hasher=payload_hasher)

    for sig, sig_name in common.SignatureIter(sigs.signatures, 'signatures'):
      sig_report = report.AddSubReport(sig_name)

      # Check: Signature contains mandatory fields.
      self._CheckMandatoryField(sig, 'version', sig_report, sig_name)
      self._CheckMandatoryField(sig, 'data', None, sig_name)
      sig_report.AddField('data len', len(sig.data))

      # Check: Signatures pertains to actual payload hash.
      if sig.version == 1:
        self._CheckSha256Signature(sig.data, pubkey_file_name,
                                   payload_hasher.digest(), sig_name)
      else:
        raise error.PayloadError('Unknown signature version (%d).' %
                                 sig.version)

  def Run(self, pubkey_file_name=None, metadata_sig_file=None,
          rootfs_part_size=0, kernel_part_size=0, report_out_file=None):
    """Checker entry point, invoking all checks.

    Args:
      pubkey_file_name: Public key used for signature verification.
      metadata_sig_file: Metadata signature, if verification is desired.
      rootfs_part_size: The size of rootfs partitions in bytes (default: infer
                        based on payload type and version).
      kernel_part_size: The size of kernel partitions in bytes (default: use
                        reported filesystem size).
      report_out_file: File object to dump the report to.

    Raises:
      error.PayloadError if payload verification failed.
    """
    if not pubkey_file_name:
      pubkey_file_name = _DEFAULT_PUBKEY_FILE_NAME

    report = _PayloadReport()

    # Get payload file size.
    self.payload.payload_file.seek(0, 2)
    payload_file_size = self.payload.payload_file.tell()
    self.payload.ResetFile()

    try:
      # Check metadata signature (if provided).
      if metadata_sig_file:
        metadata_sig = base64.b64decode(metadata_sig_file.read())
        self._CheckSha256Signature(metadata_sig, pubkey_file_name,
                                   self.payload.manifest_hasher.digest(),
                                   'metadata signature')

      # Part 1: Check the file header.
      report.AddSection('header')
      # Check: Payload version is valid.
      if self.payload.header.version != 1:
        raise error.PayloadError('Unknown payload version (%d).' %
                                 self.payload.header.version)
      report.AddField('version', self.payload.header.version)
      report.AddField('manifest len', self.payload.header.manifest_len)

      # Part 2: Check the manifest.
      self._CheckManifest(report, rootfs_part_size, kernel_part_size)
      assert self.payload_type, 'payload type should be known by now'

      # Infer the usable partition size when validating rootfs operations:
      # - If rootfs partition size was provided, use that.
      # - Otherwise, if this is an older delta (minor version < 2), stick with
      #   a known constant size. This is necessary because older deltas may
      #   exceed the filesystem size when moving data blocks around.
      # - Otherwise, use the encoded filesystem size.
      new_rootfs_usable_size = self.new_rootfs_fs_size
      if rootfs_part_size:
        new_rootfs_usable_size = rootfs_part_size
      elif self.payload_type == _TYPE_DELTA and self.minor_version in (None, 1):
        new_rootfs_usable_size = _OLD_DELTA_USABLE_PART_SIZE

      # Part 3: Examine rootfs operations.
      # TODO(garnold)(chromium:243559) only default to the filesystem size if
      # no explicit size provided *and* the partition size is not embedded in
      # the payload; see issue for more details.
      report.AddSection('rootfs operations')
      total_blob_size = self._CheckOperations(
          self.payload.manifest.install_operations, report,
          'install_operations', self.old_rootfs_fs_size,
          self.new_rootfs_fs_size, new_rootfs_usable_size, 0, False)

      # Part 4: Examine kernel operations.
      # TODO(garnold)(chromium:243559) as above.
      report.AddSection('kernel operations')
      total_blob_size += self._CheckOperations(
          self.payload.manifest.kernel_install_operations, report,
          'kernel_install_operations', self.old_kernel_fs_size,
          self.new_kernel_fs_size,
          kernel_part_size if kernel_part_size else self.new_kernel_fs_size,
          total_blob_size, True)

      # Check: Operations data reach the end of the payload file.
      used_payload_size = self.payload.data_offset + total_blob_size
      if used_payload_size != payload_file_size:
        raise error.PayloadError(
            'Used payload size (%d) different from actual file size (%d).' %
            (used_payload_size, payload_file_size))

      # Part 5: Handle payload signatures message.
      if self.check_payload_sig and self.sigs_size:
        self._CheckSignatures(report, pubkey_file_name)

      # Part 6: Summary.
      report.AddSection('summary')
      report.AddField('update type', self.payload_type)

      report.Finalize()
    finally:
      if report_out_file:
        report.Dump(report_out_file)
