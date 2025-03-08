#
# This file is part of the libsigrokdecode project.
#
# Copyright (C) 2024 Tangliufeng <tangliufeng@seneasy.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

import sigrokdecode as srd
from enum import Enum
from typing import Tuple
import binascii

LOG_DEBUG = 0  # debug log level

# 时序参数
TIME_TOL = 10  # tolerance, in percent
TIME_PREAMBLE_LOW_MS = 4  # 3 ms
TIME_PREAMBLE_HIGH_MS = 8  # 6 ms
TIME_LOGIC_LOW = 0.64
TIME_ONE_HIGH = 1.44
TIME_ZERO_HIGH = 0.48

START_CODE = 0x4C


class Status(Enum):

    IDLE = 0
    PREAMBLE = 1
    START = 2
    DATA = 3
    SUM = 4


class SamplerateError(Exception):
    pass


class Ann:
    """ Annotation index """
    BIT, PREAMBLE, START, DATA, STOP,\
    ID,FUNCTION,ARGS,SUM,\
    INVALID,DEBUG   = range(11)


class Decoder(srd.Decoder):
    api_version = 3
    id = 'jomoo_rc'
    name = 'JOMOO RC'
    longname = 'JOMOO Remote Control Protocol Decoder'
    desc = 'one wire decoder for jomoo rc.'
    license = 'gplv3+'
    inputs = ['logic']
    outputs = []
    tags = ['remote', '', 'rc', 'one-wire']
    channels = ({'id': 'data', 'name': 'DATA', 'desc': 'Data line'}, )

    options = ({
        'id': 'target_data',
        'desc': '统计比对值D[0-3](10进制)',
        'default': 00000000,
    }, )
    #（颜色编号，id， name）
    annotations = (('bit', 'Bit'),  # Bit
                   ('preamble', 'Preamble'),  # 前导码 
                   ('start', 'Start'),  # 开始位 
                   ('data', 'Data'),  # 数据 
                   ('stop', 'Stop'),  # 停止位 
                   ('id', 'ID'),  # ID Code 
                   ('function', 'Function'),  # 功能键 
                   ('args', 'Args'),  # 参数
                   ('sum', 'SUM'),  # 校验 
                   ('error', 'Error'),  # 无效数据 
                   ('debug', 'Debug'),
                   )
    annotation_rows = (('bits', 'Bits', (0, )),  # bit 解析行
                       ('packet', 'Packet', (1, 2, 3,
                                             )),  # Packet 解析行
                       ('datas', 'Datas', (6, 7, 8,
                                           )),  # 数据解析行
                       ('errors', 'Errors', (9, )),  # 错误解析行
                       ('debugs', 'Debugs', (10, )),  # 调试行
                       )

    def __init__(self):
        self.reset()

    def reset(self):
        self.state = Status.IDLE
        self.ss = 0  # Annotated start sample number
        self.es = 0  # Annotated end sample number
        self.datas = []  # 数据
        self.start_code = 0  # 开始位
        self.checksum_invalid = False  # 校验和标记
        self.datas_anchors = []  # 数据锚点
        self.total = 0
        self.pass_num = 0
        self.fail_num = 0
        self.is_statistic = False  # 是否统计

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def metadata(self, key, value):
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value  # 采样率

    def putx(self, data):
        """ Put annotation
        使用内部锚点(self.ss, self.es)，放置注释
        """
        self.put(self.ss, self.es, self.out_ann, data)
        self.ss = self.es

    def put_debug(self, data):
        """ Put debug annotation
        """
        if LOG_DEBUG:
            self.put(self.ss, self.es, self.out_ann, data)
            self.ss = self.es

    def put_label(self, anchor: tuple, data):
        """ Put label

        使用外部锚点，放置注释
        Arags: achor (label_start, label_end)
        """
        self.put(anchor[0], anchor[1], self.out_ann, data)
        self.ss = self.es

    def handle_bit(self):
        pass

    def calc_pluse_time(self, start, end):
        """
        计算脉冲时间
        """
        return (end - start) * self.interval_ms

    def check_pluse_time(self, measuretime, target_time, tol=TIME_TOL):
        """ 脉冲时间验证
        """
        return (target_time * (1 - tol / 100) <= measuretime <= target_time *
                (1 + tol / 100))

    def is_preamble(self) -> Tuple[int, tuple]:
        """
        查找前导码

        引导码: 4ms low +8ms high
        Returns: True if preamble is found, False otherwise.
        """
        # find low pluse for preamble
        self.wait({0: 'f'})
        self.ss = self.samplenum
        label_start = self.ss
        self.wait({0: 'r'})
        self.es = self.samplenum
        low_pluse_times = self.calc_pluse_time(self.ss, self.es)
        self.put_debug([Ann.DEBUG, ['{}ms'.format(low_pluse_times)]])
        self.ss = self.es

        # find high pluse for preamble
        self.wait({0: 'f'})
        self.es = self.samplenum
        label_end = self.es
        high_pluse_times = self.calc_pluse_time(self.ss, self.es)
        self.put_debug([Ann.DEBUG, ['{}ms'.format(high_pluse_times)]])
        self.ss = self.es
        anchor = (label_start, label_end)

        # check preamble
        if (self.check_pluse_time(low_pluse_times, TIME_PREAMBLE_LOW_MS)
                and self.check_pluse_time(high_pluse_times,
                                          TIME_PREAMBLE_HIGH_MS)):
            return 1, anchor
        else:
            return -1, anchor

    def is_start(self) -> bool:
        """查找开始位
            Start(0x4C)
        """
        value, anchor = self.read_byte()
        self.start_code = value
        if value != -1:  # 数据正常
            if int.from_bytes(value, 'big') == START_CODE:
                self.put_label(anchor, [
                    Ann.START,
                    ['Start (0x{})'.format(value.hex().upper()), 'Start', 'S']
                ])
                return True
            else:
                self.put_label(anchor, [Ann.START, ['Invalid', 'I']])
                return False
        else:
            self.put_label(anchor, [Ann.START, ['Invalid', 'I']])
            return False

    def read_logic_level(self) -> Tuple[int, tuple]:
        """检查逻辑电平"""
        # Low pluse
        self.wait({0: 'l'})
        label_start = self.ss = self.samplenum
        self.wait({0: 'h'})
        self.es = self.samplenum
        low_pluse_times = self.calc_pluse_time(self.ss, self.es)
        self.put_debug([Ann.DEBUG, ['{}ms'.format(low_pluse_times)]])
        self.ss = self.es
        # High pluse
        self.wait({0: 'f'})
        self.es = self.samplenum
        label_end = self.es
        high_pluse_times = self.calc_pluse_time(self.ss, self.es)
        self.put_debug([Ann.DEBUG, ['{}ms'.format(high_pluse_times)]])
        self.ss = self.es
        anchor = (label_start, label_end)
        # Verify logic level
        if (self.check_pluse_time(low_pluse_times, TIME_LOGIC_LOW)):
            if self.check_pluse_time(high_pluse_times, TIME_ZERO_HIGH):
                return 0, anchor  # Return logic 0
            elif self.check_pluse_time(high_pluse_times, TIME_ONE_HIGH):
                return 1, anchor  # Return logic 1
            else:
                return -1, anchor  # Invalid
        else:
            return -1, anchor

    def logic_to_byte(self, logic_data, msb=True):
        if msb is False:
            # 低位在前, 倒序
            logic_data = logic_data[::-1]
        # 将逻辑数据转换为二进制字符串
        binary_str = ''.join(str(bit) for bit in logic_data)
        # 将二进制字符串转换为整数
        int_val = int(binary_str, 2)
        # 将整数转换为字节
        byte_data = bytes([int_val])
        return byte_data

    def read_byte(self):
        """
        读取一个字节数据

        Returns: byte_data, anchor
        """
        logic_data = []
        label_start = None
        invalid = True
        for i in range(8):
            logic_value, anchor = self.read_logic_level()
            # Label
            if i == 0:  # 记录第一个逻辑电平的起始位置
                label_start = anchor[0]
            elif i == 7:  # 记录最后一个逻辑电平的结束位置
                label_end = anchor[1]

            if logic_value == 1:
                logic_data.append(1)
                self.put_label(anchor, [Ann.BIT, ['1']])
            elif logic_value == 0:
                logic_data.append(0)
                self.put_label(anchor, [Ann.BIT, ['0']])
            else:
                self.put_label(anchor, [Ann.BIT, ['Invalid', 'I']])
                invalid = False
        anchor = (label_start, label_end)
        if invalid:
            return self.logic_to_byte(logic_data), anchor
        else:
            return -1, anchor

    def check_sum8(self, buffer) -> bool:
        """
        计算校验和
        
        """
        sum = 0
        for byte in buffer:
            if isinstance(byte, bytes):
                sum += int.from_bytes(byte, 'big')
            else:
                sum += byte
        return sum & 0xFF

    def decode(self):
        if not self.samplerate:
            raise SamplerateError('Cannot decode without samplerate.')

        self.interval_ms = 1000 / self.samplerate  # 计算采样间隔
        self.is_statistic = False if (self.options['target_data']
                                      == 0) else True  # 是否统计
        # 循环解码
        while True:
            # 空闲
            if (self.state == Status.IDLE):

                # Find preamble
                value, anchor = self.is_preamble()
                preable_anchor = anchor
                if value:
                    self.put_label(anchor, [Ann.PREAMBLE, ['Preamble', 'P']])
                else:
                    self.put_label(anchor,
                                   [Ann.PREAMBLE, ['Invalid', 'I']])  # 无效

                self.state = Status.PREAMBLE

            elif (self.state == Status.PREAMBLE):
                #Find start code
                self.is_start()
                self.state = Status.START
            elif (self.state == Status.START):
                # Read data
                self.datas = []
                self.datas_anchors = []
                for i in range(4):
                    value, anchor = self.read_byte()

                    # Record label
                    if i == 0:  # 记录第一个数据的起始位置
                        label_start = anchor[0]
                    elif i == 3:  # 记录最后一个数据的结束位置
                        label_end = anchor[1]

                    if value != -1:  # 数据有效
                        self.datas.append(value)
                        self.datas_anchors.append(anchor)
                        if i == 0:  # 功能键标签
                            self.put_label(anchor, [
                                Ann.FUNCTION,
                                ['0x{}'.format(value.hex().upper())]
                            ])
                        else:  # 参数标签
                            self.put_label(anchor, [
                                Ann.ARGS, ['0x{}'.format(value.hex().upper())]
                            ])

                self.put_label((label_start, label_end),
                               [Ann.DATA, ['Data[0-3]', 'D']])
                self.state = Status.DATA

            elif (self.state == Status.DATA):
                # CheckSum 校验
                value, anchor = self.read_byte()
                if value != -1:
                    self.checksum_invalid = self.check_sum8(
                        self.datas) == int.from_bytes(value, 'big')
                    if (self.checksum_invalid):
                        # CheckSum
                        self.put_label(anchor, [
                            Ann.DATA,
                            ['CHECKSUM 0x{}'.format(value.hex().upper())]
                        ])
                    else:
                        self.put_label(
                            anchor,
                            [Ann.DATA, ['CHECKSUM Invalid', 'Invalid', 'I']])
                self.state = Status.SUM

            elif (self.state == Status.SUM):
                # End of packet
                (value, ) = self.wait({0: 'r'})
                self.es = self.samplenum
                self.total += 1
                # statistics 统计分析
                # self.is_statistic = True
                result_str = None
                if self.is_statistic:
                    read_bytes = b''.join(self.datas)
                    target_bytes = self.options['target_data'].to_bytes(
                        4, 'big')
                    # 比对值
                    if (read_bytes == target_bytes
                        ) and self.checksum_invalid and (int.from_bytes(
                            self.start_code, 'big') == START_CODE):
                        self.pass_num += 1
                        result_str = "PASS"
                    else:
                        self.fail_num += 1
                        result_str = "FAIL"
                    rate = self.pass_num / self.total * 100
                    self.put_label((preable_anchor[0], anchor[1]), [
                        Ann.DEBUG,
                        [
                            '统计数据(失败次/总次): 本次{},  {}/{},  {:.2f}%'.format(
                                result_str, self.fail_num, self.total, rate)
                        ]
                    ])

                self.state = Status.IDLE

            # else:
            #     (value, ) = self.wait({0: 'e'})
            #     self.es = self.samplenum
            #     # self.putx([Ann.DEBUG, ["num: {}".format(self.samplenum)]])
            #     self.ss = self.es
