# extract_android_ota_payload.py

Extract Android firmware images from an OTA payload.bin file.

With the introduction of the A/B system update, the OTA file format changed.
This tool allows to extract and decompress the firmware images packed using the 'brillo' toolset.

Incremental firmware images are not supported (source_copy, source_bsdiff operations).

## Usage

```
$ extract_android_ota_payload.py <payload.bin> [target_dir]
  <payload.bin> : file extracted from the OTA zip file or the OTA zip file
  <target_dir>  : output directory for the extracted file
```

## Example

```
$ python extract_android_ota_payload.py marlin-ota-opm4.171019.021.d1-fd6998a5.zip /tmp/
Extracting 'boot.img'
Extracting 'system.img'
Extracting 'vendor.img'
...
Extracting 'modem.img'
```

## Dependencies

```
python-protobuf
```
