# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Applying a Chrome OS update payload.

This module is used internally by the main Payload class for applying an update
payload. The interface for invoking the applier is as follows:

  applier = PayloadApplier(payload)
  applier.Run(...)

"""

from __future__ import print_function

import array
import bz2
import hashlib
import itertools
import os
import shutil
import subprocess
import sys
import tempfile

import common
from error import PayloadError


#
# Helper functions.
#
def _VerifySha256(file_obj, expected_hash, name, length=-1):
  """Verifies the SHA256 hash of a file.

  Args:
    file_obj: file object to read
    expected_hash: the hash digest we expect to be getting
    name: name string of this hash, for error reporting
    length: precise length of data to verify (optional)

  Raises:
    PayloadError if computed hash doesn't match expected one, or if fails to
    read the specified length of data.
  """
  # pylint: disable=E1101
  hasher = hashlib.sha256()
  block_length = 1024 * 1024
  max_length = length if length >= 0 else sys.maxint

  while max_length > 0:
    read_length = min(max_length, block_length)
    data = file_obj.read(read_length)
    if not data:
      break
    max_length -= len(data)
    hasher.update(data)

  if length >= 0 and max_length > 0:
    raise PayloadError(
        'insufficient data (%d instead of %d) when verifying %s' %
        (length - max_length, length, name))

  actual_hash = hasher.digest()
  if actual_hash != expected_hash:
    raise PayloadError('%s hash (%s) not as expected (%s)' %
                       (name, common.FormatSha256(actual_hash),
                        common.FormatSha256(expected_hash)))


def _ReadExtents(file_obj, extents, block_size, max_length=-1):
  """Reads data from file as defined by extent sequence.

  This tries to be efficient by not copying data as it is read in chunks.

  Args:
    file_obj: file object
    extents: sequence of block extents (offset and length)
    block_size: size of each block
    max_length: maximum length to read (optional)

  Returns:
    A character array containing the concatenated read data.
  """
  data = array.array('c')
  if max_length < 0:
    max_length = sys.maxint
  for ex in extents:
    if max_length == 0:
      break
    read_length = min(max_length, ex.num_blocks * block_size)

    # Fill with zeros or read from file, depending on the type of extent.
    if ex.start_block == common.PSEUDO_EXTENT_MARKER:
      data.extend(itertools.repeat('\0', read_length))
    else:
      file_obj.seek(ex.start_block * block_size)
      data.fromfile(file_obj, read_length)

    max_length -= read_length

  return data


def _WriteExtents(file_obj, data, extents, block_size, base_name):
  """Writes data to file as defined by extent sequence.

  This tries to be efficient by not copy data as it is written in chunks.

  Args:
    file_obj: file object
    data: data to write
    extents: sequence of block extents (offset and length)
    block_size: size of each block
    base_name: name string of extent sequence for error reporting

  Raises:
    PayloadError when things don't add up.
  """
  data_offset = 0
  data_length = len(data)
  for ex, ex_name in common.ExtentIter(extents, base_name):
    if not data_length:
      raise PayloadError('%s: more write extents than data' % ex_name)
    write_length = min(data_length, ex.num_blocks * block_size)

    # Only do actual writing if this is not a pseudo-extent.
    if ex.start_block != common.PSEUDO_EXTENT_MARKER:
      file_obj.seek(ex.start_block * block_size)
      data_view = buffer(data, data_offset, write_length)
      file_obj.write(data_view)

    data_offset += write_length
    data_length -= write_length

  if data_length:
    raise PayloadError('%s: more data than write extents' % base_name)


def _ExtentsToBspatchArg(extents, block_size, base_name, data_length=-1):
  """Translates an extent sequence into a bspatch-compatible string argument.

  Args:
    extents: sequence of block extents (offset and length)
    block_size: size of each block
    base_name: name string of extent sequence for error reporting
    data_length: the actual total length of the data in bytes (optional)

  Returns:
    A tuple consisting of (i) a string of the form
    "off_1:len_1,...,off_n:len_n", (ii) an offset where zero padding is needed
    for filling the last extent, (iii) the length of the padding (zero means no
    padding is needed and the extents cover the full length of data).

  Raises:
    PayloadError if data_length is too short or too long.
  """
  arg = ''
  pad_off = pad_len = 0
  if data_length < 0:
    data_length = sys.maxint
  for ex, ex_name in common.ExtentIter(extents, base_name):
    if not data_length:
      raise PayloadError('%s: more extents than total data length' % ex_name)

    is_pseudo = ex.start_block == common.PSEUDO_EXTENT_MARKER
    start_byte = -1 if is_pseudo else ex.start_block * block_size
    num_bytes = ex.num_blocks * block_size
    if data_length < num_bytes:
      # We're only padding a real extent.
      if not is_pseudo:
        pad_off = start_byte + data_length
        pad_len = num_bytes - data_length

      num_bytes = data_length

    arg += '%s%d:%d' % (arg and ',', start_byte, num_bytes)
    data_length -= num_bytes

  if data_length:
    raise PayloadError('%s: extents not covering full data length' % base_name)

  return arg, pad_off, pad_len


#
# Payload application.
#
class PayloadApplier(object):
  """Applying an update payload.

  This is a short-lived object whose purpose is to isolate the logic used for
  applying an update payload.
  """

  def __init__(self, payload, bsdiff_in_place=True, bspatch_path=None,
               imgpatch_path=None, truncate_to_expected_size=True):
    """Initialize the applier.

    Args:
      payload: the payload object to check
      bsdiff_in_place: whether to perform BSDIFF operation in-place (optional)
      bspatch_path: path to the bspatch binary (optional)
      imgpatch_path: path to the imgpatch binary (optional)
      truncate_to_expected_size: whether to truncate the resulting partitions
                                 to their expected sizes, as specified in the
                                 payload (optional)
    """
    assert payload.is_init, 'uninitialized update payload'
    self.payload = payload
    self.block_size = payload.manifest.block_size
    self.minor_version = payload.manifest.minor_version
    self.bsdiff_in_place = bsdiff_in_place
    self.bspatch_path = bspatch_path or 'bspatch'
    self.imgpatch_path = imgpatch_path or 'imgpatch'
    self.truncate_to_expected_size = truncate_to_expected_size

  def _ApplyReplaceOperation(self, op, op_name, out_data, part_file, part_size):
    """Applies a REPLACE{,_BZ} operation.

    Args:
      op: the operation object
      op_name: name string for error reporting
      out_data: the data to be written
      part_file: the partition file object
      part_size: the size of the partition

    Raises:
      PayloadError if something goes wrong.
    """
    block_size = self.block_size
    data_length = len(out_data)

    # Decompress data if needed.
    if op.type == common.OpType.REPLACE_BZ:
      out_data = bz2.decompress(out_data)
      data_length = len(out_data)

    # Write data to blocks specified in dst extents.
    data_start = 0
    for ex, ex_name in common.ExtentIter(op.dst_extents,
                                         '%s.dst_extents' % op_name):
      start_block = ex.start_block
      num_blocks = ex.num_blocks
      count = num_blocks * block_size

      # Make sure it's not a fake (signature) operation.
      if start_block != common.PSEUDO_EXTENT_MARKER:
        data_end = data_start + count

        # Make sure we're not running past partition boundary.
        if (start_block + num_blocks) * block_size > part_size:
          raise PayloadError(
              '%s: extent (%s) exceeds partition size (%d)' %
              (ex_name, common.FormatExtent(ex, block_size),
               part_size))

        # Make sure that we have enough data to write.
        if data_end >= data_length + block_size:
          raise PayloadError(
              '%s: more dst blocks than data (even with padding)')

        # Pad with zeros if necessary.
        if data_end > data_length:
          padding = data_end - data_length
          out_data += '\0' * padding

        self.payload.payload_file.seek(start_block * block_size)
        part_file.seek(start_block * block_size)
        part_file.write(out_data[data_start:data_end])

      data_start += count

    # Make sure we wrote all data.
    if data_start < data_length:
      raise PayloadError('%s: wrote fewer bytes (%d) than expected (%d)' %
                         (op_name, data_start, data_length))

  def _ApplyMoveOperation(self, op, op_name, part_file):
    """Applies a MOVE operation.

    Note that this operation must read the whole block data from the input and
    only then dump it, due to our in-place update semantics; otherwise, it
    might clobber data midway through.

    Args:
      op: the operation object
      op_name: name string for error reporting
      part_file: the partition file object

    Raises:
      PayloadError if something goes wrong.
    """
    block_size = self.block_size

    # Gather input raw data from src extents.
    in_data = _ReadExtents(part_file, op.src_extents, block_size)

    # Dump extracted data to dst extents.
    _WriteExtents(part_file, in_data, op.dst_extents, block_size,
                  '%s.dst_extents' % op_name)

  def _ApplyBsdiffOperation(self, op, op_name, patch_data, new_part_file):
    """Applies a BSDIFF operation.

    Args:
      op: the operation object
      op_name: name string for error reporting
      patch_data: the binary patch content
      new_part_file: the target partition file object

    Raises:
      PayloadError if something goes wrong.
    """
    # Implemented using a SOURCE_BSDIFF operation with the source and target
    # partition set to the new partition.
    self._ApplyDiffOperation(op, op_name, patch_data, new_part_file,
                             new_part_file)

  def _ApplySourceCopyOperation(self, op, op_name, old_part_file,
                                new_part_file):
    """Applies a SOURCE_COPY operation.

    Args:
      op: the operation object
      op_name: name string for error reporting
      old_part_file: the old partition file object
      new_part_file: the new partition file object

    Raises:
      PayloadError if something goes wrong.
    """
    if not old_part_file:
      raise PayloadError(
          '%s: no source partition file provided for operation type (%d)' %
          (op_name, op.type))

    block_size = self.block_size

    # Gather input raw data from src extents.
    in_data = _ReadExtents(old_part_file, op.src_extents, block_size)

    # Dump extracted data to dst extents.
    _WriteExtents(new_part_file, in_data, op.dst_extents, block_size,
                  '%s.dst_extents' % op_name)

  def _ApplyDiffOperation(self, op, op_name, patch_data, old_part_file,
                          new_part_file):
    """Applies a SOURCE_BSDIFF or IMGDIFF operation.

    Args:
      op: the operation object
      op_name: name string for error reporting
      patch_data: the binary patch content
      old_part_file: the source partition file object
      new_part_file: the target partition file object

    Raises:
      PayloadError if something goes wrong.
    """
    if not old_part_file:
      raise PayloadError(
          '%s: no source partition file provided for operation type (%d)' %
          (op_name, op.type))

    block_size = self.block_size

    # Dump patch data to file.
    with tempfile.NamedTemporaryFile(delete=False) as patch_file:
      patch_file_name = patch_file.name
      patch_file.write(patch_data)

    if (hasattr(new_part_file, 'fileno') and
        ((not old_part_file) or hasattr(old_part_file, 'fileno')) and
        op.type != common.OpType.IMGDIFF):
      # Construct input and output extents argument for bspatch.
      in_extents_arg, _, _ = _ExtentsToBspatchArg(
          op.src_extents, block_size, '%s.src_extents' % op_name,
          data_length=op.src_length)
      out_extents_arg, pad_off, pad_len = _ExtentsToBspatchArg(
          op.dst_extents, block_size, '%s.dst_extents' % op_name,
          data_length=op.dst_length)

      new_file_name = '/dev/fd/%d' % new_part_file.fileno()
      # Diff from source partition.
      old_file_name = '/dev/fd/%d' % old_part_file.fileno()

      # Invoke bspatch on partition file with extents args.
      bspatch_cmd = [self.bspatch_path, old_file_name, new_file_name,
                     patch_file_name, in_extents_arg, out_extents_arg]
      subprocess.check_call(bspatch_cmd)

      # Pad with zeros past the total output length.
      if pad_len:
        new_part_file.seek(pad_off)
        new_part_file.write('\0' * pad_len)
    else:
      # Gather input raw data and write to a temp file.
      input_part_file = old_part_file if old_part_file else new_part_file
      in_data = _ReadExtents(input_part_file, op.src_extents, block_size,
                             max_length=op.src_length)
      with tempfile.NamedTemporaryFile(delete=False) as in_file:
        in_file_name = in_file.name
        in_file.write(in_data)

      # Allocate temporary output file.
      with tempfile.NamedTemporaryFile(delete=False) as out_file:
        out_file_name = out_file.name

      # Invoke bspatch.
      patch_cmd = [self.bspatch_path, in_file_name, out_file_name,
                   patch_file_name]
      if op.type == common.OpType.IMGDIFF:
        patch_cmd[0] = self.imgpatch_path
      subprocess.check_call(patch_cmd)

      # Read output.
      with open(out_file_name, 'rb') as out_file:
        out_data = out_file.read()
        if len(out_data) != op.dst_length:
          raise PayloadError(
              '%s: actual patched data length (%d) not as expected (%d)' %
              (op_name, len(out_data), op.dst_length))

      # Write output back to partition, with padding.
      unaligned_out_len = len(out_data) % block_size
      if unaligned_out_len:
        out_data += '\0' * (block_size - unaligned_out_len)
      _WriteExtents(new_part_file, out_data, op.dst_extents, block_size,
                    '%s.dst_extents' % op_name)

      # Delete input/output files.
      os.remove(in_file_name)
      os.remove(out_file_name)

    # Delete patch file.
    os.remove(patch_file_name)

  def _ApplyOperations(self, operations, base_name, old_part_file,
                       new_part_file, part_size):
    """Applies a sequence of update operations to a partition.

    This assumes an in-place update semantics for MOVE and BSDIFF, namely all
    reads are performed first, then the data is processed and written back to
    the same file.

    Args:
      operations: the sequence of operations
      base_name: the name of the operation sequence
      old_part_file: the old partition file object, open for reading/writing
      new_part_file: the new partition file object, open for reading/writing
      part_size: the partition size

    Raises:
      PayloadError if anything goes wrong while processing the payload.
    """
    for op, op_name in common.OperationIter(operations, base_name):
      # Read data blob.
      data = self.payload.ReadDataBlob(op.data_offset, op.data_length)

      if op.type in (common.OpType.REPLACE, common.OpType.REPLACE_BZ):
        self._ApplyReplaceOperation(op, op_name, data, new_part_file, part_size)
      elif op.type == common.OpType.MOVE:
        self._ApplyMoveOperation(op, op_name, new_part_file)
      elif op.type == common.OpType.BSDIFF:
        self._ApplyBsdiffOperation(op, op_name, data, new_part_file)
      elif op.type == common.OpType.SOURCE_COPY:
        self._ApplySourceCopyOperation(op, op_name, old_part_file,
                                       new_part_file)
      elif op.type in (common.OpType.SOURCE_BSDIFF, common.OpType.IMGDIFF):
        self._ApplyDiffOperation(op, op_name, data, old_part_file,
                                 new_part_file)
      else:
        raise PayloadError('%s: unknown operation type (%d)' %
                           (op_name, op.type))

  def _ApplyToPartition(self, operations, part_name, base_name,
                        new_part_file_name, new_part_info,
                        old_part_file_name=None, old_part_info=None):
    """Applies an update to a partition.

    Args:
      operations: the sequence of update operations to apply
      part_name: the name of the partition, for error reporting
      base_name: the name of the operation sequence
      new_part_file_name: file name to write partition data to
      new_part_info: size and expected hash of dest partition
      old_part_file_name: file name of source partition (optional)
      old_part_info: size and expected hash of source partition (optional)

    Raises:
      PayloadError if anything goes wrong with the update.
    """
    # Do we have a source partition?
    if old_part_file_name:
      # Verify the source partition.
      with open(old_part_file_name, 'rb') as old_part_file:
        _VerifySha256(old_part_file, old_part_info.hash,
                      'old ' + part_name, length=old_part_info.size)
      new_part_file_mode = 'r+b'
      if self.minor_version == common.INPLACE_MINOR_PAYLOAD_VERSION:
        # Copy the src partition to the dst one; make sure we don't truncate it.
        shutil.copyfile(old_part_file_name, new_part_file_name)
      elif (self.minor_version == common.SOURCE_MINOR_PAYLOAD_VERSION or
            self.minor_version == common.OPSRCHASH_MINOR_PAYLOAD_VERSION or
            self.minor_version == common.IMGDIFF_MINOR_PAYLOAD_VERSION):
        # In minor version >= 2, we don't want to copy the partitions, so
        # instead just make the new partition file.
        open(new_part_file_name, 'w').close()
      else:
        raise PayloadError("Unknown minor version: %d" % self.minor_version)
    else:
      # We need to create/truncate the dst partition file.
      new_part_file_mode = 'w+b'

    # Apply operations.
    with open(new_part_file_name, new_part_file_mode) as new_part_file:
      old_part_file = (open(old_part_file_name, 'r+b')
                       if old_part_file_name else None)
      try:
        self._ApplyOperations(operations, base_name, old_part_file,
                              new_part_file, new_part_info.size)
      finally:
        if old_part_file:
          old_part_file.close()

      # Truncate the result, if so instructed.
      if self.truncate_to_expected_size:
        new_part_file.seek(0, 2)
        if new_part_file.tell() > new_part_info.size:
          new_part_file.seek(new_part_info.size)
          new_part_file.truncate()

    # Verify the resulting partition.
    with open(new_part_file_name, 'rb') as new_part_file:
      _VerifySha256(new_part_file, new_part_info.hash,
                    'new ' + part_name, length=new_part_info.size)

  def Run(self, new_kernel_part, new_rootfs_part, old_kernel_part=None,
          old_rootfs_part=None):
    """Applier entry point, invoking all update operations.

    Args:
      new_kernel_part: name of dest kernel partition file
      new_rootfs_part: name of dest rootfs partition file
      old_kernel_part: name of source kernel partition file (optional)
      old_rootfs_part: name of source rootfs partition file (optional)

    Raises:
      PayloadError if payload application failed.
    """
    self.payload.ResetFile()

    # Make sure the arguments are sane and match the payload.
    if not (new_kernel_part and new_rootfs_part):
      raise PayloadError('missing dst {kernel,rootfs} partitions')

    if not (old_kernel_part or old_rootfs_part):
      if not self.payload.IsFull():
        raise PayloadError('trying to apply a non-full update without src '
                           '{kernel,rootfs} partitions')
    elif old_kernel_part and old_rootfs_part:
      if not self.payload.IsDelta():
        raise PayloadError('trying to apply a non-delta update onto src '
                           '{kernel,rootfs} partitions')
    else:
      raise PayloadError('not all src partitions provided')

    # Apply update to rootfs.
    self._ApplyToPartition(
        self.payload.manifest.install_operations, 'rootfs',
        'install_operations', new_rootfs_part,
        self.payload.manifest.new_rootfs_info, old_rootfs_part,
        self.payload.manifest.old_rootfs_info)

    # Apply update to kernel update.
    self._ApplyToPartition(
        self.payload.manifest.kernel_install_operations, 'kernel',
        'kernel_install_operations', new_kernel_part,
        self.payload.manifest.new_kernel_info, old_kernel_part,
        self.payload.manifest.old_kernel_info)
