# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Library for processing, verifying and applying Chrome OS update payloads."""

# Just raise the interface classes to the root namespace.
# pylint: disable=W0401
from checker import CHECKS_TO_DISABLE
from error import PayloadError
from payload import Payload
