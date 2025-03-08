##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2016 Vladimir Ermakov <vooon341@gmail.com>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##
'''
九牧卫浴遥控器解码器 (jomoo remote control protocol decoder)

Format: |引导码|Start(0x4C)|Data(4 Byte)|CheckSum|
    :引导码: 4ms low +8ms high
    :logic 0: 0.64ms low + 0.48ms high
    :logic 1: 0.64ms low + 1.44ms high
    :字节数据, 高位在前 (MSB first)
'''

from .pd import Decoder
