#!/usr/bin/python2
#
# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unit testing checker.py."""

from __future__ import print_function

import array
import collections
import cStringIO
import hashlib
import itertools
import os
import unittest

# pylint cannot find mox.
# pylint: disable=F0401
import mox

import checker
import common
import payload as update_payload  # Avoid name conflicts later.
import test_utils
import update_metadata_pb2


def _OpTypeByName(op_name):
  op_name_to_type = {
      'REPLACE': common.OpType.REPLACE,
      'REPLACE_BZ': common.OpType.REPLACE_BZ,
      'MOVE': common.OpType.MOVE,
      'BSDIFF': common.OpType.BSDIFF,
      'SOURCE_COPY': common.OpType.SOURCE_COPY,
      'SOURCE_BSDIFF': common.OpType.SOURCE_BSDIFF,
      'ZERO': common.OpType.ZERO,
      'DISCARD': common.OpType.DISCARD,
      'REPLACE_XZ': common.OpType.REPLACE_XZ,
      'IMGDIFF': common.OpType.IMGDIFF,
  }
  return op_name_to_type[op_name]


def _GetPayloadChecker(payload_gen_write_to_file_func, payload_gen_dargs=None,
                       checker_init_dargs=None):
  """Returns a payload checker from a given payload generator."""
  if payload_gen_dargs is None:
    payload_gen_dargs = {}
  if checker_init_dargs is None:
    checker_init_dargs = {}

  payload_file = cStringIO.StringIO()
  payload_gen_write_to_file_func(payload_file, **payload_gen_dargs)
  payload_file.seek(0)
  payload = update_payload.Payload(payload_file)
  payload.Init()
  return checker.PayloadChecker(payload, **checker_init_dargs)


def _GetPayloadCheckerWithData(payload_gen):
  """Returns a payload checker from a given payload generator."""
  payload_file = cStringIO.StringIO()
  payload_gen.WriteToFile(payload_file)
  payload_file.seek(0)
  payload = update_payload.Payload(payload_file)
  payload.Init()
  return checker.PayloadChecker(payload)


# This class doesn't need an __init__().
# pylint: disable=W0232
# Unit testing is all about running protected methods.
# pylint: disable=W0212
# Don't bark about missing members of classes you cannot import.
# pylint: disable=E1101
class PayloadCheckerTest(mox.MoxTestBase):
  """Tests the PayloadChecker class.

  In addition to ordinary testFoo() methods, which are automatically invoked by
  the unittest framework, in this class we make use of DoBarTest() calls that
  implement parametric tests of certain features. In order to invoke each test,
  which embodies a unique combination of parameter values, as a complete unit
  test, we perform explicit enumeration of the parameter space and create
  individual invocation contexts for each, which are then bound as
  testBar__param1=val1__param2=val2(). The enumeration of parameter spaces for
  all such tests is done in AddAllParametricTests().
  """

  def MockPayload(self):
    """Create a mock payload object, complete with a mock manifest."""
    payload = self.mox.CreateMock(update_payload.Payload)
    payload.is_init = True
    payload.manifest = self.mox.CreateMock(
        update_metadata_pb2.DeltaArchiveManifest)
    return payload

  @staticmethod
  def NewExtent(start_block, num_blocks):
    """Returns an Extent message.

    Each of the provided fields is set iff it is >= 0; otherwise, it's left at
    its default state.

    Args:
      start_block: The starting block of the extent.
      num_blocks: The number of blocks in the extent.

    Returns:
      An Extent message.
    """
    ex = update_metadata_pb2.Extent()
    if start_block >= 0:
      ex.start_block = start_block
    if num_blocks >= 0:
      ex.num_blocks = num_blocks
    return ex

  @staticmethod
  def NewExtentList(*args):
    """Returns an list of extents.

    Args:
      *args: (start_block, num_blocks) pairs defining the extents.

    Returns:
      A list of Extent objects.
    """
    ex_list = []
    for start_block, num_blocks in args:
      ex_list.append(PayloadCheckerTest.NewExtent(start_block, num_blocks))
    return ex_list

  @staticmethod
  def AddToMessage(repeated_field, field_vals):
    for field_val in field_vals:
      new_field = repeated_field.add()
      new_field.CopyFrom(field_val)

  def SetupAddElemTest(self, is_present, is_submsg, convert=str,
                       linebreak=False, indent=0):
    """Setup for testing of _CheckElem() and its derivatives.

    Args:
      is_present: Whether or not the element is found in the message.
      is_submsg: Whether the element is a sub-message itself.
      convert: A representation conversion function.
      linebreak: Whether or not a linebreak is to be used in the report.
      indent: Indentation used for the report.

    Returns:
      msg: A mock message object.
      report: A mock report object.
      subreport: A mock sub-report object.
      name: An element name to check.
      val: Expected element value.
    """
    name = 'foo'
    val = 'fake submsg' if is_submsg else 'fake field'
    subreport = 'fake subreport'

    # Create a mock message.
    msg = self.mox.CreateMock(update_metadata_pb2._message.Message)
    msg.HasField(name).AndReturn(is_present)
    setattr(msg, name, val)

    # Create a mock report.
    report = self.mox.CreateMock(checker._PayloadReport)
    if is_present:
      if is_submsg:
        report.AddSubReport(name).AndReturn(subreport)
      else:
        report.AddField(name, convert(val), linebreak=linebreak, indent=indent)

    self.mox.ReplayAll()
    return (msg, report, subreport, name, val)

  def DoAddElemTest(self, is_present, is_mandatory, is_submsg, convert,
                    linebreak, indent):
    """Parametric testing of _CheckElem().

    Args:
      is_present: Whether or not the element is found in the message.
      is_mandatory: Whether or not it's a mandatory element.
      is_submsg: Whether the element is a sub-message itself.
      convert: A representation conversion function.
      linebreak: Whether or not a linebreak is to be used in the report.
      indent: Indentation used for the report.
    """
    msg, report, subreport, name, val = self.SetupAddElemTest(
        is_present, is_submsg, convert, linebreak, indent)

    args = (msg, name, report, is_mandatory, is_submsg)
    kwargs = {'convert': convert, 'linebreak': linebreak, 'indent': indent}
    if is_mandatory and not is_present:
      self.assertRaises(update_payload.PayloadError,
                        checker.PayloadChecker._CheckElem, *args, **kwargs)
    else:
      ret_val, ret_subreport = checker.PayloadChecker._CheckElem(*args,
                                                                 **kwargs)
      self.assertEquals(val if is_present else None, ret_val)
      self.assertEquals(subreport if is_present and is_submsg else None,
                        ret_subreport)

  def DoAddFieldTest(self, is_mandatory, is_present, convert, linebreak,
                     indent):
    """Parametric testing of _Check{Mandatory,Optional}Field().

    Args:
      is_mandatory: Whether we're testing a mandatory call.
      is_present: Whether or not the element is found in the message.
      convert: A representation conversion function.
      linebreak: Whether or not a linebreak is to be used in the report.
      indent: Indentation used for the report.
    """
    msg, report, _, name, val = self.SetupAddElemTest(
        is_present, False, convert, linebreak, indent)

    # Prepare for invocation of the tested method.
    args = [msg, name, report]
    kwargs = {'convert': convert, 'linebreak': linebreak, 'indent': indent}
    if is_mandatory:
      args.append('bar')
      tested_func = checker.PayloadChecker._CheckMandatoryField
    else:
      tested_func = checker.PayloadChecker._CheckOptionalField

    # Test the method call.
    if is_mandatory and not is_present:
      self.assertRaises(update_payload.PayloadError, tested_func, *args,
                        **kwargs)
    else:
      ret_val = tested_func(*args, **kwargs)
      self.assertEquals(val if is_present else None, ret_val)

  def DoAddSubMsgTest(self, is_mandatory, is_present):
    """Parametrized testing of _Check{Mandatory,Optional}SubMsg().

    Args:
      is_mandatory: Whether we're testing a mandatory call.
      is_present: Whether or not the element is found in the message.
    """
    msg, report, subreport, name, val = self.SetupAddElemTest(is_present, True)

    # Prepare for invocation of the tested method.
    args = [msg, name, report]
    if is_mandatory:
      args.append('bar')
      tested_func = checker.PayloadChecker._CheckMandatorySubMsg
    else:
      tested_func = checker.PayloadChecker._CheckOptionalSubMsg

    # Test the method call.
    if is_mandatory and not is_present:
      self.assertRaises(update_payload.PayloadError, tested_func, *args)
    else:
      ret_val, ret_subreport = tested_func(*args)
      self.assertEquals(val if is_present else None, ret_val)
      self.assertEquals(subreport if is_present else None, ret_subreport)

  def testCheckPresentIff(self):
    """Tests _CheckPresentIff()."""
    self.assertIsNone(checker.PayloadChecker._CheckPresentIff(
        None, None, 'foo', 'bar', 'baz'))
    self.assertIsNone(checker.PayloadChecker._CheckPresentIff(
        'a', 'b', 'foo', 'bar', 'baz'))
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckPresentIff,
                      'a', None, 'foo', 'bar', 'baz')
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckPresentIff,
                      None, 'b', 'foo', 'bar', 'baz')

  def DoCheckSha256SignatureTest(self, expect_pass, expect_subprocess_call,
                                 sig_data, sig_asn1_header,
                                 returned_signed_hash, expected_signed_hash):
    """Parametric testing of _CheckSha256SignatureTest().

    Args:
      expect_pass: Whether or not it should pass.
      expect_subprocess_call: Whether to expect the openssl call to happen.
      sig_data: The signature raw data.
      sig_asn1_header: The ASN1 header.
      returned_signed_hash: The signed hash data retuned by openssl.
      expected_signed_hash: The signed hash data to compare against.
    """
    try:
      # Stub out the subprocess invocation.
      self.mox.StubOutWithMock(checker.PayloadChecker, '_Run')
      if expect_subprocess_call:
        checker.PayloadChecker._Run(
            mox.IsA(list), send_data=sig_data).AndReturn(
                (sig_asn1_header + returned_signed_hash, None))

      self.mox.ReplayAll()
      if expect_pass:
        self.assertIsNone(checker.PayloadChecker._CheckSha256Signature(
            sig_data, 'foo', expected_signed_hash, 'bar'))
      else:
        self.assertRaises(update_payload.PayloadError,
                          checker.PayloadChecker._CheckSha256Signature,
                          sig_data, 'foo', expected_signed_hash, 'bar')
    finally:
      self.mox.UnsetStubs()

  def testCheckSha256Signature_Pass(self):
    """Tests _CheckSha256Signature(); pass case."""
    sig_data = 'fake-signature'.ljust(256)
    signed_hash = hashlib.sha256('fake-data').digest()
    self.DoCheckSha256SignatureTest(True, True, sig_data,
                                    common.SIG_ASN1_HEADER, signed_hash,
                                    signed_hash)

  def testCheckSha256Signature_FailBadSignature(self):
    """Tests _CheckSha256Signature(); fails due to malformed signature."""
    sig_data = 'fake-signature'  # Malformed (not 256 bytes in length).
    signed_hash = hashlib.sha256('fake-data').digest()
    self.DoCheckSha256SignatureTest(False, False, sig_data,
                                    common.SIG_ASN1_HEADER, signed_hash,
                                    signed_hash)

  def testCheckSha256Signature_FailBadOutputLength(self):
    """Tests _CheckSha256Signature(); fails due to unexpected output length."""
    sig_data = 'fake-signature'.ljust(256)
    signed_hash = 'fake-hash'  # Malformed (not 32 bytes in length).
    self.DoCheckSha256SignatureTest(False, True, sig_data,
                                    common.SIG_ASN1_HEADER, signed_hash,
                                    signed_hash)

  def testCheckSha256Signature_FailBadAsnHeader(self):
    """Tests _CheckSha256Signature(); fails due to bad ASN1 header."""
    sig_data = 'fake-signature'.ljust(256)
    signed_hash = hashlib.sha256('fake-data').digest()
    bad_asn1_header = 'bad-asn-header'.ljust(len(common.SIG_ASN1_HEADER))
    self.DoCheckSha256SignatureTest(False, True, sig_data, bad_asn1_header,
                                    signed_hash, signed_hash)

  def testCheckSha256Signature_FailBadHash(self):
    """Tests _CheckSha256Signature(); fails due to bad hash returned."""
    sig_data = 'fake-signature'.ljust(256)
    expected_signed_hash = hashlib.sha256('fake-data').digest()
    returned_signed_hash = hashlib.sha256('bad-fake-data').digest()
    self.DoCheckSha256SignatureTest(False, True, sig_data,
                                    common.SIG_ASN1_HEADER,
                                    expected_signed_hash, returned_signed_hash)

  def testCheckBlocksFitLength_Pass(self):
    """Tests _CheckBlocksFitLength(); pass case."""
    self.assertIsNone(checker.PayloadChecker._CheckBlocksFitLength(
        64, 4, 16, 'foo'))
    self.assertIsNone(checker.PayloadChecker._CheckBlocksFitLength(
        60, 4, 16, 'foo'))
    self.assertIsNone(checker.PayloadChecker._CheckBlocksFitLength(
        49, 4, 16, 'foo'))
    self.assertIsNone(checker.PayloadChecker._CheckBlocksFitLength(
        48, 3, 16, 'foo'))

  def testCheckBlocksFitLength_TooManyBlocks(self):
    """Tests _CheckBlocksFitLength(); fails due to excess blocks."""
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckBlocksFitLength,
                      64, 5, 16, 'foo')
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckBlocksFitLength,
                      60, 5, 16, 'foo')
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckBlocksFitLength,
                      49, 5, 16, 'foo')
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckBlocksFitLength,
                      48, 4, 16, 'foo')

  def testCheckBlocksFitLength_TooFewBlocks(self):
    """Tests _CheckBlocksFitLength(); fails due to insufficient blocks."""
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckBlocksFitLength,
                      64, 3, 16, 'foo')
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckBlocksFitLength,
                      60, 3, 16, 'foo')
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckBlocksFitLength,
                      49, 3, 16, 'foo')
    self.assertRaises(update_payload.PayloadError,
                      checker.PayloadChecker._CheckBlocksFitLength,
                      48, 2, 16, 'foo')

  def DoCheckManifestTest(self, fail_mismatched_block_size, fail_bad_sigs,
                          fail_mismatched_oki_ori, fail_bad_oki, fail_bad_ori,
                          fail_bad_nki, fail_bad_nri, fail_old_kernel_fs_size,
                          fail_old_rootfs_fs_size, fail_new_kernel_fs_size,
                          fail_new_rootfs_fs_size):
    """Parametric testing of _CheckManifest().

    Args:
      fail_mismatched_block_size: Simulate a missing block_size field.
      fail_bad_sigs: Make signatures descriptor inconsistent.
      fail_mismatched_oki_ori: Make old rootfs/kernel info partially present.
      fail_bad_oki: Tamper with old kernel info.
      fail_bad_ori: Tamper with old rootfs info.
      fail_bad_nki: Tamper with new kernel info.
      fail_bad_nri: Tamper with new rootfs info.
      fail_old_kernel_fs_size: Make old kernel fs size too big.
      fail_old_rootfs_fs_size: Make old rootfs fs size too big.
      fail_new_kernel_fs_size: Make new kernel fs size too big.
      fail_new_rootfs_fs_size: Make new rootfs fs size too big.
    """
    # Generate a test payload. For this test, we only care about the manifest
    # and don't need any data blobs, hence we can use a plain paylaod generator
    # (which also gives us more control on things that can be screwed up).
    payload_gen = test_utils.PayloadGenerator()

    # Tamper with block size, if required.
    if fail_mismatched_block_size:
      payload_gen.SetBlockSize(test_utils.KiB(1))
    else:
      payload_gen.SetBlockSize(test_utils.KiB(4))

    # Add some operations.
    payload_gen.AddOperation(False, common.OpType.MOVE,
                             src_extents=[(0, 16), (16, 497)],
                             dst_extents=[(16, 496), (0, 16)])
    payload_gen.AddOperation(True, common.OpType.MOVE,
                             src_extents=[(0, 8), (8, 8)],
                             dst_extents=[(8, 8), (0, 8)])

    # Set an invalid signatures block (offset but no size), if required.
    if fail_bad_sigs:
      payload_gen.SetSignatures(32, None)

    # Set partition / filesystem sizes.
    rootfs_part_size = test_utils.MiB(8)
    kernel_part_size = test_utils.KiB(512)
    old_rootfs_fs_size = new_rootfs_fs_size = rootfs_part_size
    old_kernel_fs_size = new_kernel_fs_size = kernel_part_size
    if fail_old_kernel_fs_size:
      old_kernel_fs_size += 100
    if fail_old_rootfs_fs_size:
      old_rootfs_fs_size += 100
    if fail_new_kernel_fs_size:
      new_kernel_fs_size += 100
    if fail_new_rootfs_fs_size:
      new_rootfs_fs_size += 100

    # Add old kernel/rootfs partition info, as required.
    if fail_mismatched_oki_ori or fail_old_kernel_fs_size or fail_bad_oki:
      oki_hash = (None if fail_bad_oki
                  else hashlib.sha256('fake-oki-content').digest())
      payload_gen.SetPartInfo(True, False, old_kernel_fs_size, oki_hash)
    if not fail_mismatched_oki_ori and (fail_old_rootfs_fs_size or
                                        fail_bad_ori):
      ori_hash = (None if fail_bad_ori
                  else hashlib.sha256('fake-ori-content').digest())
      payload_gen.SetPartInfo(False, False, old_rootfs_fs_size, ori_hash)

    # Add new kernel/rootfs partition info.
    payload_gen.SetPartInfo(
        True, True, new_kernel_fs_size,
        None if fail_bad_nki else hashlib.sha256('fake-nki-content').digest())
    payload_gen.SetPartInfo(
        False, True, new_rootfs_fs_size,
        None if fail_bad_nri else hashlib.sha256('fake-nri-content').digest())

    # Set the minor version.
    payload_gen.SetMinorVersion(0)

    # Create the test object.
    payload_checker = _GetPayloadChecker(payload_gen.WriteToFile)
    report = checker._PayloadReport()

    should_fail = (fail_mismatched_block_size or fail_bad_sigs or
                   fail_mismatched_oki_ori or fail_bad_oki or fail_bad_ori or
                   fail_bad_nki or fail_bad_nri or fail_old_kernel_fs_size or
                   fail_old_rootfs_fs_size or fail_new_kernel_fs_size or
                   fail_new_rootfs_fs_size)
    if should_fail:
      self.assertRaises(update_payload.PayloadError,
                        payload_checker._CheckManifest, report,
                        rootfs_part_size, kernel_part_size)
    else:
      self.assertIsNone(payload_checker._CheckManifest(report,
                                                       rootfs_part_size,
                                                       kernel_part_size))

  def testCheckLength(self):
    """Tests _CheckLength()."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    block_size = payload_checker.block_size

    # Passes.
    self.assertIsNone(payload_checker._CheckLength(
        int(3.5 * block_size), 4, 'foo', 'bar'))
    # Fails, too few blocks.
    self.assertRaises(update_payload.PayloadError,
                      payload_checker._CheckLength,
                      int(3.5 * block_size), 3, 'foo', 'bar')
    # Fails, too many blocks.
    self.assertRaises(update_payload.PayloadError,
                      payload_checker._CheckLength,
                      int(3.5 * block_size), 5, 'foo', 'bar')

  def testCheckExtents(self):
    """Tests _CheckExtents()."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    block_size = payload_checker.block_size

    # Passes w/ all real extents.
    extents = self.NewExtentList((0, 4), (8, 3), (1024, 16))
    self.assertEquals(
        23,
        payload_checker._CheckExtents(extents, (1024 + 16) * block_size,
                                      collections.defaultdict(int), 'foo'))

    # Passes w/ pseudo-extents (aka sparse holes).
    extents = self.NewExtentList((0, 4), (common.PSEUDO_EXTENT_MARKER, 5),
                                 (8, 3))
    self.assertEquals(
        12,
        payload_checker._CheckExtents(extents, (1024 + 16) * block_size,
                                      collections.defaultdict(int), 'foo',
                                      allow_pseudo=True))

    # Passes w/ pseudo-extent due to a signature.
    extents = self.NewExtentList((common.PSEUDO_EXTENT_MARKER, 2))
    self.assertEquals(
        2,
        payload_checker._CheckExtents(extents, (1024 + 16) * block_size,
                                      collections.defaultdict(int), 'foo',
                                      allow_signature=True))

    # Fails, extent missing a start block.
    extents = self.NewExtentList((-1, 4), (8, 3), (1024, 16))
    self.assertRaises(
        update_payload.PayloadError, payload_checker._CheckExtents,
        extents, (1024 + 16) * block_size, collections.defaultdict(int),
        'foo')

    # Fails, extent missing block count.
    extents = self.NewExtentList((0, -1), (8, 3), (1024, 16))
    self.assertRaises(
        update_payload.PayloadError, payload_checker._CheckExtents,
        extents, (1024 + 16) * block_size, collections.defaultdict(int),
        'foo')

    # Fails, extent has zero blocks.
    extents = self.NewExtentList((0, 4), (8, 3), (1024, 0))
    self.assertRaises(
        update_payload.PayloadError, payload_checker._CheckExtents,
        extents, (1024 + 16) * block_size, collections.defaultdict(int),
        'foo')

    # Fails, extent exceeds partition boundaries.
    extents = self.NewExtentList((0, 4), (8, 3), (1024, 16))
    self.assertRaises(
        update_payload.PayloadError, payload_checker._CheckExtents,
        extents, (1024 + 15) * block_size, collections.defaultdict(int),
        'foo')

  def testCheckReplaceOperation(self):
    """Tests _CheckReplaceOperation() where op.type == REPLACE."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    block_size = payload_checker.block_size
    data_length = 10000

    op = self.mox.CreateMock(
        update_metadata_pb2.InstallOperation)
    op.type = common.OpType.REPLACE

    # Pass.
    op.src_extents = []
    self.assertIsNone(
        payload_checker._CheckReplaceOperation(
            op, data_length, (data_length + block_size - 1) / block_size,
            'foo'))

    # Fail, src extents founds.
    op.src_extents = ['bar']
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckReplaceOperation,
        op, data_length, (data_length + block_size - 1) / block_size, 'foo')

    # Fail, missing data.
    op.src_extents = []
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckReplaceOperation,
        op, None, (data_length + block_size - 1) / block_size, 'foo')

    # Fail, length / block number mismatch.
    op.src_extents = ['bar']
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckReplaceOperation,
        op, data_length, (data_length + block_size - 1) / block_size + 1, 'foo')

  def testCheckReplaceBzOperation(self):
    """Tests _CheckReplaceOperation() where op.type == REPLACE_BZ."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    block_size = payload_checker.block_size
    data_length = block_size * 3

    op = self.mox.CreateMock(
        update_metadata_pb2.InstallOperation)
    op.type = common.OpType.REPLACE_BZ

    # Pass.
    op.src_extents = []
    self.assertIsNone(
        payload_checker._CheckReplaceOperation(
            op, data_length, (data_length + block_size - 1) / block_size + 5,
            'foo'))

    # Fail, src extents founds.
    op.src_extents = ['bar']
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckReplaceOperation,
        op, data_length, (data_length + block_size - 1) / block_size + 5, 'foo')

    # Fail, missing data.
    op.src_extents = []
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckReplaceOperation,
        op, None, (data_length + block_size - 1) / block_size, 'foo')

    # Fail, too few blocks to justify BZ.
    op.src_extents = []
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckReplaceOperation,
        op, data_length, (data_length + block_size - 1) / block_size, 'foo')

  def testCheckMoveOperation_Pass(self):
    """Tests _CheckMoveOperation(); pass case."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    op = update_metadata_pb2.InstallOperation()
    op.type = common.OpType.MOVE

    self.AddToMessage(op.src_extents,
                      self.NewExtentList((1, 4), (12, 2), (1024, 128)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((16, 128), (512, 6)))
    self.assertIsNone(
        payload_checker._CheckMoveOperation(op, None, 134, 134, 'foo'))

  def testCheckMoveOperation_FailContainsData(self):
    """Tests _CheckMoveOperation(); fails, message contains data."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    op = update_metadata_pb2.InstallOperation()
    op.type = common.OpType.MOVE

    self.AddToMessage(op.src_extents,
                      self.NewExtentList((1, 4), (12, 2), (1024, 128)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((16, 128), (512, 6)))
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckMoveOperation,
        op, 1024, 134, 134, 'foo')

  def testCheckMoveOperation_FailInsufficientSrcBlocks(self):
    """Tests _CheckMoveOperation(); fails, not enough actual src blocks."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    op = update_metadata_pb2.InstallOperation()
    op.type = common.OpType.MOVE

    self.AddToMessage(op.src_extents,
                      self.NewExtentList((1, 4), (12, 2), (1024, 127)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((16, 128), (512, 6)))
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckMoveOperation,
        op, None, 134, 134, 'foo')

  def testCheckMoveOperation_FailInsufficientDstBlocks(self):
    """Tests _CheckMoveOperation(); fails, not enough actual dst blocks."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    op = update_metadata_pb2.InstallOperation()
    op.type = common.OpType.MOVE

    self.AddToMessage(op.src_extents,
                      self.NewExtentList((1, 4), (12, 2), (1024, 128)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((16, 128), (512, 5)))
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckMoveOperation,
        op, None, 134, 134, 'foo')

  def testCheckMoveOperation_FailExcessSrcBlocks(self):
    """Tests _CheckMoveOperation(); fails, too many actual src blocks."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    op = update_metadata_pb2.InstallOperation()
    op.type = common.OpType.MOVE

    self.AddToMessage(op.src_extents,
                      self.NewExtentList((1, 4), (12, 2), (1024, 128)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((16, 128), (512, 5)))
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckMoveOperation,
        op, None, 134, 134, 'foo')
    self.AddToMessage(op.src_extents,
                      self.NewExtentList((1, 4), (12, 2), (1024, 129)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((16, 128), (512, 6)))
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckMoveOperation,
        op, None, 134, 134, 'foo')

  def testCheckMoveOperation_FailExcessDstBlocks(self):
    """Tests _CheckMoveOperation(); fails, too many actual dst blocks."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    op = update_metadata_pb2.InstallOperation()
    op.type = common.OpType.MOVE

    self.AddToMessage(op.src_extents,
                      self.NewExtentList((1, 4), (12, 2), (1024, 128)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((16, 128), (512, 7)))
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckMoveOperation,
        op, None, 134, 134, 'foo')

  def testCheckMoveOperation_FailStagnantBlocks(self):
    """Tests _CheckMoveOperation(); fails, there are blocks that do not move."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    op = update_metadata_pb2.InstallOperation()
    op.type = common.OpType.MOVE

    self.AddToMessage(op.src_extents,
                      self.NewExtentList((1, 4), (12, 2), (1024, 128)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((8, 128), (512, 6)))
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckMoveOperation,
        op, None, 134, 134, 'foo')

  def testCheckMoveOperation_FailZeroStartBlock(self):
    """Tests _CheckMoveOperation(); fails, has extent with start block 0."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    op = update_metadata_pb2.InstallOperation()
    op.type = common.OpType.MOVE

    self.AddToMessage(op.src_extents,
                      self.NewExtentList((0, 4), (12, 2), (1024, 128)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((8, 128), (512, 6)))
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckMoveOperation,
        op, None, 134, 134, 'foo')

    self.AddToMessage(op.src_extents,
                      self.NewExtentList((1, 4), (12, 2), (1024, 128)))
    self.AddToMessage(op.dst_extents,
                      self.NewExtentList((0, 128), (512, 6)))
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckMoveOperation,
        op, None, 134, 134, 'foo')

  def testCheckAnyDiff(self):
    """Tests _CheckAnyDiffOperation()."""
    payload_checker = checker.PayloadChecker(self.MockPayload())

    # Pass.
    self.assertIsNone(
        payload_checker._CheckAnyDiffOperation(10000, 3, 'foo'))

    # Fail, missing data blob.
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckAnyDiffOperation,
        None, 3, 'foo')

    # Fail, too big of a diff blob (unjustified).
    self.assertRaises(
        update_payload.PayloadError,
        payload_checker._CheckAnyDiffOperation,
        10000, 2, 'foo')

  def testCheckSourceCopyOperation_Pass(self):
    """Tests _CheckSourceCopyOperation(); pass case."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    self.assertIsNone(
        payload_checker._CheckSourceCopyOperation(None, 134, 134, 'foo'))

  def testCheckSourceCopyOperation_FailContainsData(self):
    """Tests _CheckSourceCopyOperation(); message contains data."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    self.assertRaises(update_payload.PayloadError,
                      payload_checker._CheckSourceCopyOperation,
                      134, 0, 0, 'foo')

  def testCheckSourceCopyOperation_FailBlockCountsMismatch(self):
    """Tests _CheckSourceCopyOperation(); src and dst block totals not equal."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    self.assertRaises(update_payload.PayloadError,
                      payload_checker._CheckSourceCopyOperation,
                      None, 0, 1, 'foo')

  def DoCheckOperationTest(self, op_type_name, is_last, allow_signature,
                           allow_unhashed, fail_src_extents, fail_dst_extents,
                           fail_mismatched_data_offset_length,
                           fail_missing_dst_extents, fail_src_length,
                           fail_dst_length, fail_data_hash,
                           fail_prev_data_offset, fail_bad_minor_version):
    """Parametric testing of _CheckOperation().

    Args:
      op_type_name: 'REPLACE', 'REPLACE_BZ', 'MOVE', 'BSDIFF', 'SOURCE_COPY',
        or 'SOURCE_BSDIFF'.
      is_last: Whether we're testing the last operation in a sequence.
      allow_signature: Whether we're testing a signature-capable operation.
      allow_unhashed: Whether we're allowing to not hash the data.
      fail_src_extents: Tamper with src extents.
      fail_dst_extents: Tamper with dst extents.
      fail_mismatched_data_offset_length: Make data_{offset,length}
        inconsistent.
      fail_missing_dst_extents: Do not include dst extents.
      fail_src_length: Make src length inconsistent.
      fail_dst_length: Make dst length inconsistent.
      fail_data_hash: Tamper with the data blob hash.
      fail_prev_data_offset: Make data space uses incontiguous.
      fail_bad_minor_version: Make minor version incompatible with op.
    """
    op_type = _OpTypeByName(op_type_name)

    # Create the test object.
    payload = self.MockPayload()
    payload_checker = checker.PayloadChecker(payload,
                                             allow_unhashed=allow_unhashed)
    block_size = payload_checker.block_size

    # Create auxiliary arguments.
    old_part_size = test_utils.MiB(4)
    new_part_size = test_utils.MiB(8)
    old_block_counters = array.array(
        'B', [0] * ((old_part_size + block_size - 1) / block_size))
    new_block_counters = array.array(
        'B', [0] * ((new_part_size + block_size - 1) / block_size))
    prev_data_offset = 1876
    blob_hash_counts = collections.defaultdict(int)

    # Create the operation object for the test.
    op = update_metadata_pb2.InstallOperation()
    op.type = op_type

    total_src_blocks = 0
    if op_type in (common.OpType.MOVE, common.OpType.BSDIFF,
                   common.OpType.SOURCE_COPY, common.OpType.SOURCE_BSDIFF):
      if fail_src_extents:
        self.AddToMessage(op.src_extents,
                          self.NewExtentList((1, 0)))
      else:
        self.AddToMessage(op.src_extents,
                          self.NewExtentList((1, 16)))
        total_src_blocks = 16

    if op_type in (common.OpType.REPLACE, common.OpType.REPLACE_BZ):
      payload_checker.minor_version = 0
    elif op_type in (common.OpType.MOVE, common.OpType.BSDIFF):
      payload_checker.minor_version = 2 if fail_bad_minor_version else 1
    elif op_type in (common.OpType.SOURCE_COPY, common.OpType.SOURCE_BSDIFF):
      payload_checker.minor_version = 1 if fail_bad_minor_version else 2

    if op_type not in (common.OpType.MOVE, common.OpType.SOURCE_COPY):
      if not fail_mismatched_data_offset_length:
        op.data_length = 16 * block_size - 8
      if fail_prev_data_offset:
        op.data_offset = prev_data_offset + 16
      else:
        op.data_offset = prev_data_offset

      fake_data = 'fake-data'.ljust(op.data_length)
      if not (allow_unhashed or (is_last and allow_signature and
                                 op_type == common.OpType.REPLACE)):
        if not fail_data_hash:
          # Create a valid data blob hash.
          op.data_sha256_hash = hashlib.sha256(fake_data).digest()
          payload.ReadDataBlob(op.data_offset, op.data_length).AndReturn(
              fake_data)
      elif fail_data_hash:
        # Create an invalid data blob hash.
        op.data_sha256_hash = hashlib.sha256(
            fake_data.replace(' ', '-')).digest()
        payload.ReadDataBlob(op.data_offset, op.data_length).AndReturn(
            fake_data)

    total_dst_blocks = 0
    if not fail_missing_dst_extents:
      total_dst_blocks = 16
      if fail_dst_extents:
        self.AddToMessage(op.dst_extents,
                          self.NewExtentList((4, 16), (32, 0)))
      else:
        self.AddToMessage(op.dst_extents,
                          self.NewExtentList((4, 8), (64, 8)))

    if total_src_blocks:
      if fail_src_length:
        op.src_length = total_src_blocks * block_size + 8
      else:
        op.src_length = total_src_blocks * block_size
    elif fail_src_length:
      # Add an orphaned src_length.
      op.src_length = 16

    if total_dst_blocks:
      if fail_dst_length:
        op.dst_length = total_dst_blocks * block_size + 8
      else:
        op.dst_length = total_dst_blocks * block_size

    self.mox.ReplayAll()
    should_fail = (fail_src_extents or fail_dst_extents or
                   fail_mismatched_data_offset_length or
                   fail_missing_dst_extents or fail_src_length or
                   fail_dst_length or fail_data_hash or fail_prev_data_offset or
                   fail_bad_minor_version)
    args = (op, 'foo', is_last, old_block_counters, new_block_counters,
            old_part_size, new_part_size, prev_data_offset, allow_signature,
            blob_hash_counts)
    if should_fail:
      self.assertRaises(update_payload.PayloadError,
                        payload_checker._CheckOperation, *args)
    else:
      self.assertEqual(op.data_length if op.HasField('data_length') else 0,
                       payload_checker._CheckOperation(*args))

  def testAllocBlockCounters(self):
    """Tests _CheckMoveOperation()."""
    payload_checker = checker.PayloadChecker(self.MockPayload())
    block_size = payload_checker.block_size

    # Check allocation for block-aligned partition size, ensure it's integers.
    result = payload_checker._AllocBlockCounters(16 * block_size)
    self.assertEqual(16, len(result))
    self.assertEqual(int, type(result[0]))

    # Check allocation of unaligned partition sizes.
    result = payload_checker._AllocBlockCounters(16 * block_size - 1)
    self.assertEqual(16, len(result))
    result = payload_checker._AllocBlockCounters(16 * block_size + 1)
    self.assertEqual(17, len(result))

  def DoCheckOperationsTest(self, fail_nonexhaustive_full_update):
    # Generate a test payload. For this test, we only care about one
    # (arbitrary) set of operations, so we'll only be generating kernel and
    # test with them.
    payload_gen = test_utils.PayloadGenerator()

    block_size = test_utils.KiB(4)
    payload_gen.SetBlockSize(block_size)

    rootfs_part_size = test_utils.MiB(8)

    # Fake rootfs operations in a full update, tampered with as required.
    rootfs_op_type = common.OpType.REPLACE
    rootfs_data_length = rootfs_part_size
    if fail_nonexhaustive_full_update:
      rootfs_data_length -= block_size

    payload_gen.AddOperation(False, rootfs_op_type,
                             dst_extents=[(0, rootfs_data_length / block_size)],
                             data_offset=0,
                             data_length=rootfs_data_length)

    # Create the test object.
    payload_checker = _GetPayloadChecker(payload_gen.WriteToFile,
                                         checker_init_dargs={
                                             'allow_unhashed': True})
    payload_checker.payload_type = checker._TYPE_FULL
    report = checker._PayloadReport()

    args = (payload_checker.payload.manifest.install_operations, report,
            'foo', 0, rootfs_part_size, rootfs_part_size, 0, False)
    if fail_nonexhaustive_full_update:
      self.assertRaises(update_payload.PayloadError,
                        payload_checker._CheckOperations, *args)
    else:
      self.assertEqual(rootfs_data_length,
                       payload_checker._CheckOperations(*args))

  def DoCheckSignaturesTest(self, fail_empty_sigs_blob, fail_missing_pseudo_op,
                            fail_mismatched_pseudo_op, fail_sig_missing_fields,
                            fail_unknown_sig_version, fail_incorrect_sig):
    # Generate a test payload. For this test, we only care about the signature
    # block and how it relates to the payload hash. Therefore, we're generating
    # a random (otherwise useless) payload for this purpose.
    payload_gen = test_utils.EnhancedPayloadGenerator()
    block_size = test_utils.KiB(4)
    payload_gen.SetBlockSize(block_size)
    rootfs_part_size = test_utils.MiB(2)
    kernel_part_size = test_utils.KiB(16)
    payload_gen.SetPartInfo(False, True, rootfs_part_size,
                            hashlib.sha256('fake-new-rootfs-content').digest())
    payload_gen.SetPartInfo(True, True, kernel_part_size,
                            hashlib.sha256('fake-new-kernel-content').digest())
    payload_gen.SetMinorVersion(0)
    payload_gen.AddOperationWithData(
        False, common.OpType.REPLACE,
        dst_extents=[(0, rootfs_part_size / block_size)],
        data_blob=os.urandom(rootfs_part_size))

    do_forge_pseudo_op = (fail_missing_pseudo_op or fail_mismatched_pseudo_op)
    do_forge_sigs_data = (do_forge_pseudo_op or fail_empty_sigs_blob or
                          fail_sig_missing_fields or fail_unknown_sig_version
                          or fail_incorrect_sig)

    sigs_data = None
    if do_forge_sigs_data:
      sigs_gen = test_utils.SignaturesGenerator()
      if not fail_empty_sigs_blob:
        if fail_sig_missing_fields:
          sig_data = None
        else:
          sig_data = test_utils.SignSha256('fake-payload-content',
                                           test_utils._PRIVKEY_FILE_NAME)
        sigs_gen.AddSig(5 if fail_unknown_sig_version else 1, sig_data)

      sigs_data = sigs_gen.ToBinary()
      payload_gen.SetSignatures(payload_gen.curr_offset, len(sigs_data))

    if do_forge_pseudo_op:
      assert sigs_data is not None, 'should have forged signatures blob by now'
      sigs_len = len(sigs_data)
      payload_gen.AddOperation(
          False, common.OpType.REPLACE,
          data_offset=payload_gen.curr_offset / 2,
          data_length=sigs_len / 2,
          dst_extents=[(0, (sigs_len / 2 + block_size - 1) / block_size)])

    # Generate payload (complete w/ signature) and create the test object.
    payload_checker = _GetPayloadChecker(
        payload_gen.WriteToFileWithData,
        payload_gen_dargs={
            'sigs_data': sigs_data,
            'privkey_file_name': test_utils._PRIVKEY_FILE_NAME,
            'do_add_pseudo_operation': not do_forge_pseudo_op})
    payload_checker.payload_type = checker._TYPE_FULL
    report = checker._PayloadReport()

    # We have to check the manifest first in order to set signature attributes.
    payload_checker._CheckManifest(report, rootfs_part_size, kernel_part_size)

    should_fail = (fail_empty_sigs_blob or fail_missing_pseudo_op or
                   fail_mismatched_pseudo_op or fail_sig_missing_fields or
                   fail_unknown_sig_version or fail_incorrect_sig)
    args = (report, test_utils._PUBKEY_FILE_NAME)
    if should_fail:
      self.assertRaises(update_payload.PayloadError,
                        payload_checker._CheckSignatures, *args)
    else:
      self.assertIsNone(payload_checker._CheckSignatures(*args))

  def DoCheckManifestMinorVersionTest(self, minor_version, payload_type):
    """Parametric testing for CheckManifestMinorVersion().

    Args:
      minor_version: The payload minor version to test with.
      payload_type: The type of the payload we're testing, delta or full.
    """
    # Create the test object.
    payload = self.MockPayload()
    payload.manifest.minor_version = minor_version
    payload_checker = checker.PayloadChecker(payload)
    payload_checker.payload_type = payload_type
    report = checker._PayloadReport()

    should_succeed = (
        (minor_version == 0 and payload_type == checker._TYPE_FULL) or
        (minor_version == 1 and payload_type == checker._TYPE_DELTA) or
        (minor_version == 2 and payload_type == checker._TYPE_DELTA) or
        (minor_version == 3 and payload_type == checker._TYPE_DELTA) or
        (minor_version == 4 and payload_type == checker._TYPE_DELTA))
    args = (report,)

    if should_succeed:
      self.assertIsNone(payload_checker._CheckManifestMinorVersion(*args))
    else:
      self.assertRaises(update_payload.PayloadError,
                        payload_checker._CheckManifestMinorVersion, *args)

  def DoRunTest(self, rootfs_part_size_provided, kernel_part_size_provided,
                fail_wrong_payload_type, fail_invalid_block_size,
                fail_mismatched_block_size, fail_excess_data,
                fail_rootfs_part_size_exceeded,
                fail_kernel_part_size_exceeded):
    # Generate a test payload. For this test, we generate a full update that
    # has sample kernel and rootfs operations. Since most testing is done with
    # internal PayloadChecker methods that are tested elsewhere, here we only
    # tamper with what's actually being manipulated and/or tested in the Run()
    # method itself. Note that the checker doesn't verify partition hashes, so
    # they're safe to fake.
    payload_gen = test_utils.EnhancedPayloadGenerator()
    block_size = test_utils.KiB(4)
    payload_gen.SetBlockSize(block_size)
    kernel_filesystem_size = test_utils.KiB(16)
    rootfs_filesystem_size = test_utils.MiB(2)
    payload_gen.SetPartInfo(False, True, rootfs_filesystem_size,
                            hashlib.sha256('fake-new-rootfs-content').digest())
    payload_gen.SetPartInfo(True, True, kernel_filesystem_size,
                            hashlib.sha256('fake-new-kernel-content').digest())
    payload_gen.SetMinorVersion(0)

    rootfs_part_size = 0
    if rootfs_part_size_provided:
      rootfs_part_size = rootfs_filesystem_size + block_size
    rootfs_op_size = rootfs_part_size or rootfs_filesystem_size
    if fail_rootfs_part_size_exceeded:
      rootfs_op_size += block_size
    payload_gen.AddOperationWithData(
        False, common.OpType.REPLACE,
        dst_extents=[(0, rootfs_op_size / block_size)],
        data_blob=os.urandom(rootfs_op_size))

    kernel_part_size = 0
    if kernel_part_size_provided:
      kernel_part_size = kernel_filesystem_size + block_size
    kernel_op_size = kernel_part_size or kernel_filesystem_size
    if fail_kernel_part_size_exceeded:
      kernel_op_size += block_size
    payload_gen.AddOperationWithData(
        True, common.OpType.REPLACE,
        dst_extents=[(0, kernel_op_size / block_size)],
        data_blob=os.urandom(kernel_op_size))

    # Generate payload (complete w/ signature) and create the test object.
    if fail_invalid_block_size:
      use_block_size = block_size + 5  # Not a power of two.
    elif fail_mismatched_block_size:
      use_block_size = block_size * 2  # Different that payload stated.
    else:
      use_block_size = block_size

    kwargs = {
        'payload_gen_dargs': {
            'privkey_file_name': test_utils._PRIVKEY_FILE_NAME,
            'do_add_pseudo_operation': True,
            'is_pseudo_in_kernel': True,
            'padding': os.urandom(1024) if fail_excess_data else None},
        'checker_init_dargs': {
            'assert_type': 'delta' if fail_wrong_payload_type else 'full',
            'block_size': use_block_size}}
    if fail_invalid_block_size:
      self.assertRaises(update_payload.PayloadError, _GetPayloadChecker,
                        payload_gen.WriteToFileWithData, **kwargs)
    else:
      payload_checker = _GetPayloadChecker(payload_gen.WriteToFileWithData,
                                           **kwargs)

      kwargs = {'pubkey_file_name': test_utils._PUBKEY_FILE_NAME,
                'rootfs_part_size': rootfs_part_size,
                'kernel_part_size': kernel_part_size}
      should_fail = (fail_wrong_payload_type or fail_mismatched_block_size or
                     fail_excess_data or
                     fail_rootfs_part_size_exceeded or
                     fail_kernel_part_size_exceeded)
      if should_fail:
        self.assertRaises(update_payload.PayloadError, payload_checker.Run,
                          **kwargs)
      else:
        self.assertIsNone(payload_checker.Run(**kwargs))

# This implements a generic API, hence the occasional unused args.
# pylint: disable=W0613
def ValidateCheckOperationTest(op_type_name, is_last, allow_signature,
                               allow_unhashed, fail_src_extents,
                               fail_dst_extents,
                               fail_mismatched_data_offset_length,
                               fail_missing_dst_extents, fail_src_length,
                               fail_dst_length, fail_data_hash,
                               fail_prev_data_offset, fail_bad_minor_version):
  """Returns True iff the combination of arguments represents a valid test."""
  op_type = _OpTypeByName(op_type_name)

  # REPLACE/REPLACE_BZ operations don't read data from src partition. They are
  # compatible with all valid minor versions, so we don't need to check that.
  if (op_type in (common.OpType.REPLACE, common.OpType.REPLACE_BZ) and (
      fail_src_extents or fail_src_length or fail_bad_minor_version)):
    return False

  # MOVE and SOURCE_COPY operations don't carry data.
  if (op_type in (common.OpType.MOVE, common.OpType.SOURCE_COPY) and (
      fail_mismatched_data_offset_length or fail_data_hash or
      fail_prev_data_offset)):
    return False

  return True


def TestMethodBody(run_method_name, run_dargs):
  """Returns a function that invokes a named method with named arguments."""
  return lambda self: getattr(self, run_method_name)(**run_dargs)


def AddParametricTests(tested_method_name, arg_space, validate_func=None):
  """Enumerates and adds specific parametric tests to PayloadCheckerTest.

  This function enumerates a space of test parameters (defined by arg_space),
  then binds a new, unique method name in PayloadCheckerTest to a test function
  that gets handed the said parameters. This is a preferable approach to doing
  the enumeration and invocation during the tests because this way each test is
  treated as a complete run by the unittest framework, and so benefits from the
  usual setUp/tearDown mechanics.

  Args:
    tested_method_name: Name of the tested PayloadChecker method.
    arg_space: A dictionary containing variables (keys) and lists of values
               (values) associated with them.
    validate_func: A function used for validating test argument combinations.
  """
  for value_tuple in itertools.product(*arg_space.itervalues()):
    run_dargs = dict(zip(arg_space.iterkeys(), value_tuple))
    if validate_func and not validate_func(**run_dargs):
      continue
    run_method_name = 'Do%sTest' % tested_method_name
    test_method_name = 'test%s' % tested_method_name
    for arg_key, arg_val in run_dargs.iteritems():
      if arg_val or type(arg_val) is int:
        test_method_name += '__%s=%s' % (arg_key, arg_val)
    setattr(PayloadCheckerTest, test_method_name,
            TestMethodBody(run_method_name, run_dargs))


def AddAllParametricTests():
  """Enumerates and adds all parametric tests to PayloadCheckerTest."""
  # Add all _CheckElem() test cases.
  AddParametricTests('AddElem',
                     {'linebreak': (True, False),
                      'indent': (0, 1, 2),
                      'convert': (str, lambda s: s[::-1]),
                      'is_present': (True, False),
                      'is_mandatory': (True, False),
                      'is_submsg': (True, False)})

  # Add all _Add{Mandatory,Optional}Field tests.
  AddParametricTests('AddField',
                     {'is_mandatory': (True, False),
                      'linebreak': (True, False),
                      'indent': (0, 1, 2),
                      'convert': (str, lambda s: s[::-1]),
                      'is_present': (True, False)})

  # Add all _Add{Mandatory,Optional}SubMsg tests.
  AddParametricTests('AddSubMsg',
                     {'is_mandatory': (True, False),
                      'is_present': (True, False)})

  # Add all _CheckManifest() test cases.
  AddParametricTests('CheckManifest',
                     {'fail_mismatched_block_size': (True, False),
                      'fail_bad_sigs': (True, False),
                      'fail_mismatched_oki_ori': (True, False),
                      'fail_bad_oki': (True, False),
                      'fail_bad_ori': (True, False),
                      'fail_bad_nki': (True, False),
                      'fail_bad_nri': (True, False),
                      'fail_old_kernel_fs_size': (True, False),
                      'fail_old_rootfs_fs_size': (True, False),
                      'fail_new_kernel_fs_size': (True, False),
                      'fail_new_rootfs_fs_size': (True, False)})

  # Add all _CheckOperation() test cases.
  AddParametricTests('CheckOperation',
                     {'op_type_name': ('REPLACE', 'REPLACE_BZ', 'MOVE',
                                       'BSDIFF', 'SOURCE_COPY',
                                       'SOURCE_BSDIFF'),
                      'is_last': (True, False),
                      'allow_signature': (True, False),
                      'allow_unhashed': (True, False),
                      'fail_src_extents': (True, False),
                      'fail_dst_extents': (True, False),
                      'fail_mismatched_data_offset_length': (True, False),
                      'fail_missing_dst_extents': (True, False),
                      'fail_src_length': (True, False),
                      'fail_dst_length': (True, False),
                      'fail_data_hash': (True, False),
                      'fail_prev_data_offset': (True, False),
                      'fail_bad_minor_version': (True, False)},
                     validate_func=ValidateCheckOperationTest)

  # Add all _CheckOperations() test cases.
  AddParametricTests('CheckOperations',
                     {'fail_nonexhaustive_full_update': (True, False)})

  # Add all _CheckOperations() test cases.
  AddParametricTests('CheckSignatures',
                     {'fail_empty_sigs_blob': (True, False),
                      'fail_missing_pseudo_op': (True, False),
                      'fail_mismatched_pseudo_op': (True, False),
                      'fail_sig_missing_fields': (True, False),
                      'fail_unknown_sig_version': (True, False),
                      'fail_incorrect_sig': (True, False)})

  # Add all _CheckManifestMinorVersion() test cases.
  AddParametricTests('CheckManifestMinorVersion',
                     {'minor_version': (None, 0, 1, 2, 3, 4, 555),
                      'payload_type': (checker._TYPE_FULL,
                                       checker._TYPE_DELTA)})

  # Add all Run() test cases.
  AddParametricTests('Run',
                     {'rootfs_part_size_provided': (True, False),
                      'kernel_part_size_provided': (True, False),
                      'fail_wrong_payload_type': (True, False),
                      'fail_invalid_block_size': (True, False),
                      'fail_mismatched_block_size': (True, False),
                      'fail_excess_data': (True, False),
                      'fail_rootfs_part_size_exceeded': (True, False),
                      'fail_kernel_part_size_exceeded': (True, False)})


if __name__ == '__main__':
  AddAllParametricTests()
  unittest.main()
