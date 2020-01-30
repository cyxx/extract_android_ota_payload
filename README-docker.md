Run in Docker
---
To unpack payload.bin we start from the Docker image [continuumio/miniconda](https://hub.docker.com/r/continuumio/miniconda/) to install dependencies via [Miniconda](https://docs.conda.io/en/latest/miniconda.html):
```
docker run --name payload.bin --rm -it \
   -v `pwd`"/data":/opt/data \
   continuumio/miniconda /bin/bash
```

In the container we install protobuf and clone the project:
```
conda install protobuf --yes
git clone --depth=1 https://github.com/cyxx/extract_android_ota_payload.git /opt/bin
```

Next download and unzip and OTA image, e.g. for [Oneplus](https://www.oneplus.com/de/support/softwareupgrade/):
```
url=https://oxygenos.oneplus.net/OnePlus6Oxygen_22_OTA_034_all_1909112343_31f86cec5f8d4c7b.zip
wget --output-document=/opt/data/image.zip $url
python -m zipfile -e /opt/data/image.zip /opt/data/image
```

And finally unpack the payload.bin:
```
python /opt/bin/extract_android_ota_payload.py /opt/data/image/payload.bin /opt/data/payload
```
