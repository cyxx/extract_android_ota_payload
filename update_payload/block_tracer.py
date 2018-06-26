# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tracing block data source through a Chrome OS update payload.

This module is used internally by the main Payload class for tracing block
content through an update payload. This is a useful feature in debugging
payload applying functionality in this package. The interface for invoking the
tracer is as follows:

  tracer = PayloadBlockTracer(payload)
  tracer.Run(...)

"""

from __future__ import print_function

import common


#
# Payload block tracing.
#
class PayloadBlockTracer(object):
  """Tracing the origin of block data through update instructions.

  This is a short-lived object whose purpose is to isolate the logic used for
  tracing the origin of destination partition blocks.

  """

  def __init__(self, payload):
    assert payload.is_init, 'uninitialized update payload'
    self.payload = payload

  @staticmethod
  def _TraceBlock(block, skip, trace_out_file, operations, base_name):
    """Trace the origin of a given block through a sequence of operations.

    This method tries to map the given dest block to the corresponding source
    block from which its content originates in the course of an update. It
    further tries to trace transitive origins through MOVE operations. It is
    rather efficient, doing the actual tracing by means of a single reverse
    sweep through the operation sequence. It dumps a log of operations and
    source blocks responsible for the data in the given dest block to the
    provided output file.

    Args:
      block: the block number to trace
      skip: number of initial transitive origins to ignore
      trace_out_file: a file object to dump the trace to
      operations: the sequence of operations
      base_name: name of the operation sequence
    """
    # Traverse operations backwards.
    for op, op_name in common.OperationIter(operations, base_name,
                                            reverse=True):
      total_block_offset = 0
      found = False

      # Is the traced block mentioned in the dest extents?
      for dst_ex, dst_ex_name in common.ExtentIter(op.dst_extents,
                                                   op_name + '.dst_extents'):
        if (block >= dst_ex.start_block
            and block < dst_ex.start_block + dst_ex.num_blocks):
          if skip:
            skip -= 1
          else:
            total_block_offset += block - dst_ex.start_block
            trace_out_file.write(
                '%d: %s: found %s (total block offset: %d)\n' %
                (block, dst_ex_name, common.FormatExtent(dst_ex),
                 total_block_offset))
            found = True
            break

        total_block_offset += dst_ex.num_blocks

      if found:
        # Don't trace further, unless it's a MOVE.
        if op.type != common.OpType.MOVE:
          break

        # For MOVE, find corresponding source block and keep tracing.
        for src_ex, src_ex_name in common.ExtentIter(op.src_extents,
                                                     op_name + '.src_extents'):
          if total_block_offset < src_ex.num_blocks:
            block = src_ex.start_block + total_block_offset
            trace_out_file.write(
                '%s:  mapped to %s (%d)\n' %
                (src_ex_name, common.FormatExtent(src_ex), block))
            break

          total_block_offset -= src_ex.num_blocks

  def Run(self, block, skip, trace_out_file, is_kernel):
    """Block tracer entry point, invoking the actual search.

    Args:
      block: the block number whose origin to trace
      skip: the number of first origin mappings to skip
      trace_out_file: file object to dump the trace to
      is_kernel: trace through kernel (True) or rootfs (False) operations
    """
    if is_kernel:
      operations = self.payload.manifest.kernel_install_operations
      base_name = 'kernel_install_operations'
    else:
      operations = self.payload.manifest.install_operations
      base_name = 'install_operations'

    self._TraceBlock(block, skip, trace_out_file, operations, base_name)
