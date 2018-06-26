# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tools for reading, verifying and applying Chrome OS update payloads."""

from __future__ import print_function

import hashlib
import struct

import applier
import block_tracer
import checker
import common
from error import PayloadError
import update_metadata_pb2


#
# Helper functions.
#
def _ReadInt(file_obj, size, is_unsigned, hasher=None):
  """Reads a binary-encoded integer from a file.

  It will do the correct conversion based on the reported size and whether or
  not a signed number is expected. Assumes a network (big-endian) byte
  ordering.

  Args:
    file_obj: a file object
    size: the integer size in bytes (2, 4 or 8)
    is_unsigned: whether it is signed or not
    hasher: an optional hasher to pass the value through

  Returns:
    An "unpacked" (Python) integer value.

  Raises:
    PayloadError if an read error occurred.
  """
  return struct.unpack(common.IntPackingFmtStr(size, is_unsigned),
                       common.Read(file_obj, size, hasher=hasher))[0]


#
# Update payload.
#
class Payload(object):
  """Chrome OS update payload processor."""

  class _PayloadHeader(object):
    """Update payload header struct."""

    # Header constants; sizes are in bytes.
    _MAGIC = 'CrAU'
    _VERSION_SIZE = 8
    _MANIFEST_LEN_SIZE = 8
    _METADATA_SIGNATURE_LEN_SIZE = 4

    def __init__(self):
      self.version = None
      self.manifest_len = None
      self.metadata_signature_len = None
      self.size = None

    def ReadFromPayload(self, payload_file, hasher=None):
      """Reads the payload header from a file.

      Reads the payload header from the |payload_file| and updates the |hasher|
      if one is passed. The parsed header is stored in the _PayloadHeader
      instance attributes.

      Args:
        payload_file: a file object
        hasher: an optional hasher to pass the value through

      Returns:
        None.

      Raises:
        PayloadError if a read error occurred or the header is invalid.
      """
      # Verify magic
      magic = common.Read(payload_file, len(self._MAGIC), hasher=hasher)
      if magic != self._MAGIC:
        raise PayloadError('invalid payload magic: %s' % magic)

      self.version = _ReadInt(payload_file, self._VERSION_SIZE, True,
                              hasher=hasher)
      self.manifest_len = _ReadInt(payload_file, self._MANIFEST_LEN_SIZE, True,
                                   hasher=hasher)
      self.size = (len(self._MAGIC) + self._VERSION_SIZE +
                   self._MANIFEST_LEN_SIZE)
      self.metadata_signature_len = 0
      if self.version == common.BRILLO_MAJOR_PAYLOAD_VERSION:
        self.size += self._METADATA_SIGNATURE_LEN_SIZE
        self.metadata_signature_len = _ReadInt(
            payload_file, self._METADATA_SIGNATURE_LEN_SIZE, True,
            hasher=hasher)


  def __init__(self, payload_file):
    """Initialize the payload object.

    Args:
      payload_file: update payload file object open for reading
    """
    self.payload_file = payload_file
    self.manifest_hasher = None
    self.is_init = False
    self.header = None
    self.manifest = None
    self.data_offset = None
    self.metadata_signature = None
    self.metadata_size = None

  def _ReadHeader(self):
    """Reads and returns the payload header.

    Returns:
      A payload header object.

    Raises:
      PayloadError if a read error occurred.
    """
    header = self._PayloadHeader()
    header.ReadFromPayload(self.payload_file, self.manifest_hasher)
    return header

  def _ReadManifest(self):
    """Reads and returns the payload manifest.

    Returns:
      A string containing the payload manifest in binary form.

    Raises:
      PayloadError if a read error occurred.
    """
    if not self.header:
      raise PayloadError('payload header not present')

    return common.Read(self.payload_file, self.header.manifest_len,
                       hasher=self.manifest_hasher)

  def _ReadMetadataSignature(self):
    """Reads and returns the metadata signatures.

    Returns:
      A string containing the metadata signatures protobuf in binary form or
      an empty string if no metadata signature found in the payload.

    Raises:
      PayloadError if a read error occurred.
    """
    if not self.header:
      raise PayloadError('payload header not present')

    return common.Read(
        self.payload_file, self.header.metadata_signature_len,
        offset=self.header.size + self.header.manifest_len)

  def ReadDataBlob(self, offset, length):
    """Reads and returns a single data blob from the update payload.

    Args:
      offset: offset to the beginning of the blob from the end of the manifest
      length: the blob's length

    Returns:
      A string containing the raw blob data.

    Raises:
      PayloadError if a read error occurred.
    """
    return common.Read(self.payload_file, length,
                       offset=self.data_offset + offset)

  def Init(self):
    """Initializes the payload object.

    This is a prerequisite for any other public API call.

    Raises:
      PayloadError if object already initialized or fails to initialize
      correctly.
    """
    if self.is_init:
      raise PayloadError('payload object already initialized')

    # Initialize hash context.
    # pylint: disable=E1101
    self.manifest_hasher = hashlib.sha256()

    # Read the file header.
    self.header = self._ReadHeader()

    # Read the manifest.
    manifest_raw = self._ReadManifest()
    self.manifest = update_metadata_pb2.DeltaArchiveManifest()
    self.manifest.ParseFromString(manifest_raw)

    # Read the metadata signature (if any).
    metadata_signature_raw = self._ReadMetadataSignature()
    if metadata_signature_raw:
      self.metadata_signature = update_metadata_pb2.Signatures()
      self.metadata_signature.ParseFromString(metadata_signature_raw)

    self.metadata_size = self.header.size + self.header.manifest_len
    self.data_offset = self.metadata_size + self.header.metadata_signature_len

    self.is_init = True

  def Describe(self):
    """Emits the payload embedded description data to standard output."""
    def _DescribeImageInfo(description, image_info):
      def _DisplayIndentedValue(name, value):
        print('  {:<14} {}'.format(name+':', value))

      print('%s:' % description)
      _DisplayIndentedValue('Channel', image_info.channel)
      _DisplayIndentedValue('Board', image_info.board)
      _DisplayIndentedValue('Version', image_info.version)
      _DisplayIndentedValue('Key', image_info.key)

      if image_info.build_channel != image_info.channel:
        _DisplayIndentedValue('Build channel', image_info.build_channel)

      if image_info.build_version != image_info.version:
        _DisplayIndentedValue('Build version', image_info.build_version)

    if self.manifest.HasField('old_image_info'):
      # pylint: disable=E1101
      _DescribeImageInfo('Old Image', self.manifest.old_image_info)

    if self.manifest.HasField('new_image_info'):
      # pylint: disable=E1101
      _DescribeImageInfo('New Image', self.manifest.new_image_info)

  def _AssertInit(self):
    """Raises an exception if the object was not initialized."""
    if not self.is_init:
      raise PayloadError('payload object not initialized')

  def ResetFile(self):
    """Resets the offset of the payload file to right past the manifest."""
    self.payload_file.seek(self.data_offset)

  def IsDelta(self):
    """Returns True iff the payload appears to be a delta."""
    self._AssertInit()
    return (self.manifest.HasField('old_kernel_info') or
            self.manifest.HasField('old_rootfs_info') or
            any(partition.HasField('old_partition_info')
                for partition in self.manifest.partitions))

  def IsFull(self):
    """Returns True iff the payload appears to be a full."""
    return not self.IsDelta()

  def Check(self, pubkey_file_name=None, metadata_sig_file=None,
            report_out_file=None, assert_type=None, block_size=0,
            rootfs_part_size=0, kernel_part_size=0, allow_unhashed=False,
            disabled_tests=()):
    """Checks the payload integrity.

    Args:
      pubkey_file_name: public key used for signature verification
      metadata_sig_file: metadata signature, if verification is desired
      report_out_file: file object to dump the report to
      assert_type: assert that payload is either 'full' or 'delta'
      block_size: expected filesystem / payload block size
      rootfs_part_size: the size of (physical) rootfs partitions in bytes
      kernel_part_size: the size of (physical) kernel partitions in bytes
      allow_unhashed: allow unhashed operation blobs
      disabled_tests: list of tests to disable

    Raises:
      PayloadError if payload verification failed.
    """
    self._AssertInit()

    # Create a short-lived payload checker object and run it.
    helper = checker.PayloadChecker(
        self, assert_type=assert_type, block_size=block_size,
        allow_unhashed=allow_unhashed, disabled_tests=disabled_tests)
    helper.Run(pubkey_file_name=pubkey_file_name,
               metadata_sig_file=metadata_sig_file,
               rootfs_part_size=rootfs_part_size,
               kernel_part_size=kernel_part_size,
               report_out_file=report_out_file)

  def Apply(self, new_kernel_part, new_rootfs_part, old_kernel_part=None,
            old_rootfs_part=None, bsdiff_in_place=True, bspatch_path=None,
            truncate_to_expected_size=True):
    """Applies the update payload.

    Args:
      new_kernel_part: name of dest kernel partition file
      new_rootfs_part: name of dest rootfs partition file
      old_kernel_part: name of source kernel partition file (optional)
      old_rootfs_part: name of source rootfs partition file (optional)
      bsdiff_in_place: whether to perform BSDIFF operations in-place (optional)
      bspatch_path: path to the bspatch binary (optional)
      truncate_to_expected_size: whether to truncate the resulting partitions
                                 to their expected sizes, as specified in the
                                 payload (optional)

    Raises:
      PayloadError if payload application failed.
    """
    self._AssertInit()

    # Create a short-lived payload applier object and run it.
    helper = applier.PayloadApplier(
        self, bsdiff_in_place=bsdiff_in_place, bspatch_path=bspatch_path,
        truncate_to_expected_size=truncate_to_expected_size)
    helper.Run(new_kernel_part, new_rootfs_part,
               old_kernel_part=old_kernel_part,
               old_rootfs_part=old_rootfs_part)

  def TraceBlock(self, block, skip, trace_out_file, is_kernel):
    """Traces the origin(s) of a given dest partition block.

    The tracing tries to find origins transitively, when possible (it currently
    only works for move operations, where the mapping of src/dst is
    one-to-one). It will dump a list of operations and source blocks
    responsible for the data in the given dest block.

    Args:
      block: the block number whose origin to trace
      skip: the number of first origin mappings to skip
      trace_out_file: file object to dump the trace to
      is_kernel: trace through kernel (True) or rootfs (False) operations
    """
    self._AssertInit()

    # Create a short-lived payload block tracer object and run it.
    helper = block_tracer.PayloadBlockTracer(self)
    helper.Run(block, skip, trace_out_file, is_kernel)
