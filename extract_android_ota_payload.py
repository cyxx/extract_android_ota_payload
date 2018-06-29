#!/usr/bin/env python

import hashlib
import os
import os.path
import shutil
import subprocess
import sys
import zipfile

# from https://android.googlesource.com/platform/system/update_engine/scripts/
import update_payload

PROGRAMS = [ 'bzcat', 'xzcat' ]

def decompress_payload(command, data, size, hash):
  p = subprocess.Popen([command, '-'], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
  r = p.communicate(data)[0]
  if len(r) != size:
    print("Unexpected size %d %d" % (len(r), size))
  elif hashlib.sha256(data).digest() != hash:
    print("Hash mismatch")
  return r

def parse_payload(payload_f, partition, out_f):
  BLOCK_SIZE = 4096
  for operation in partition.operations:
    e = operation.dst_extents[0]
    data = payload_f.ReadDataBlob(operation.data_offset, operation.data_length)
    out_f.seek(e.start_block * BLOCK_SIZE)
    if operation.type == update_payload.common.OpType.REPLACE:
      out_f.write(data)
    elif operation.type == update_payload.common.OpType.REPLACE_XZ:
      r = decompress_payload('xzcat', data, e.num_blocks * BLOCK_SIZE, operation.data_sha256_hash)
      out_f.write(r)
    elif operation.type == update_payload.common.OpType.REPLACE_BZ:
      r = decompress_payload('bzcat', data, e.num_blocks * BLOCK_SIZE, operation.data_sha256_hash)
      out_f.write(r)
    else:
      raise update_payload.error.PayloadError('Unknown operation type (%d)' % operation.type)

def main(argv):
  try:
    filename = argv[1]
  except:
    print('Usage: %s payload.bin [output_dir]' % argv[0])
    sys.exit()

  try:
    output_dir = argv[2]
  except IndexError:
    output_dir = os.getcwd()

  if filename.endswith('.zip'):
    print("Extracting 'payload.bin' from OTA file...")
    ota_zf = zipfile.ZipFile(filename)
    payload_file = open(ota_zf.extract('payload.bin', output_dir))
  else:
    payload_file = file(filename)

  payload = update_payload.Payload(payload_file)
  payload.Init()
  payload.Describe()

  if payload.header.version != update_payload.common.BRILLO_MAJOR_PAYLOAD_VERSION:
    print('Unsupported payload version (%d)' % payload.header.version)
  else:
    for p in payload.manifest.partitions:
      name = p.partition_name + '.img'
      print("Extracting '%s'" % name)
      out_f = open(os.path.join(output_dir, name), 'w')
      parse_payload(payload, p, out_f)

if __name__ == '__main__':
  main(sys.argv)
