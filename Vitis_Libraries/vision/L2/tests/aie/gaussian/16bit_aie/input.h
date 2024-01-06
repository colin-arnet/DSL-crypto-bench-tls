/*
 * Copyright 2021 Xilinx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

int16_t int16input[] = {
    0,   0,   128, 16,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   206, 206, 206, 206, 211, 212, 205, 207, 207, 207, 207, 207, 209, 209,
    209, 210, 210, 210, 211, 212, 212, 212, 212, 212, 212, 212, 214, 214, 213, 213, 213, 213, 213, 214, 214, 215, 215,
    215, 216, 216, 218, 217, 218, 218, 218, 219, 219, 220, 221, 220, 221, 222, 222, 223, 222, 224, 224, 224, 224, 224,
    226, 225, 227, 227, 227, 228, 229, 229, 228, 230, 230, 230, 232, 232, 232, 233, 235, 234, 236, 236, 235, 235, 237,
    237, 238, 238, 238, 237, 239, 239, 240, 239, 241, 243, 242, 242, 243, 242, 243, 242, 242, 244, 247, 247, 247, 245,
    243, 244, 244, 244, 244, 243, 243, 243, 244, 246, 246, 246, 246, 247, 247, 247, 247, 247, 247, 247, 248, 246, 206,
    206, 206, 206, 208, 207, 206, 206, 207, 207, 208, 209, 208, 209, 209, 211, 210, 211, 212, 212, 212, 212, 212, 212,
    213, 213, 213, 213, 213, 213, 214, 213, 213, 214, 215, 215, 215, 215, 215, 218, 217, 218, 218, 218, 219, 218, 219,
    220, 219, 221, 221, 222, 221, 223, 222, 224, 224, 224, 224, 224, 225, 225, 227, 227, 227, 228, 228, 229, 230, 230,
    230, 232, 232, 232, 232, 234, 234, 234, 236, 235, 235, 235, 236, 238, 237, 238, 237, 239, 238, 239, 240, 240, 240,
    242, 242, 243, 244, 242, 242, 243, 242, 245, 248, 247, 246, 244, 244, 244, 244, 244, 244, 245, 243, 245, 244, 244,
    246, 246, 247, 246, 247, 247, 247, 247, 247, 248, 248, 248, 207, 207, 206, 206, 207, 207, 206, 207, 207, 207, 208,
    209, 208, 209, 211, 211, 211, 210, 212, 212, 212, 212, 212, 212, 212, 212, 213, 212, 212, 213, 213, 214, 214, 215,
    215, 215, 215, 215, 216, 217, 217, 217, 218, 218, 219, 219, 219, 219, 221, 221, 220, 222, 222, 223, 223, 223, 224,
    224, 224, 225, 225, 225, 225, 226, 228, 228, 229, 229, 229, 230, 230, 231, 231, 234, 235, 234, 235, 235, 236, 235,
    235, 236, 236, 236, 237, 236, 239, 238, 239, 239, 239, 241, 242, 243, 243, 243, 243, 243, 243, 242, 243, 245, 246,
    247, 244, 243, 244, 244, 244, 243, 244, 245, 244, 243, 245, 245, 246, 247, 246, 247, 247, 247, 247, 247, 247, 248,
    247, 247, 207, 206, 206, 207, 207, 207, 207, 206, 207, 208, 208, 210, 208, 209, 210, 210, 211, 210, 212, 211, 211,
    212, 212, 212, 212, 212, 212, 212, 213, 213, 213, 214, 214, 214, 214, 215, 215, 216, 217, 215, 218, 217, 218, 218,
    219, 219, 219, 220, 220, 221, 221, 222, 222, 223, 223, 222, 223, 225, 224, 223, 224, 225, 225, 227, 227, 228, 229,
    229, 230, 231, 231, 232, 232, 233, 234, 234, 234, 235, 236, 235, 236, 236, 236, 237, 236, 237, 238, 239, 239, 239,
    240, 241, 243, 242, 243, 243, 243, 244, 243, 243, 243, 246, 245, 244, 244, 244, 245, 245, 245, 245, 245, 246, 244,
    244, 245, 246, 246, 247, 247, 246, 247, 247, 247, 247, 247, 247, 248, 247, 206, 207, 210, 211, 214, 207, 207, 207,
    207, 208, 209, 209, 209, 210, 210, 210, 210, 210, 212, 210, 211, 212, 212, 212, 212, 213, 211, 212, 213, 213, 214,
    213, 213, 214, 215, 215, 216, 215, 216, 217, 217, 218, 218, 218, 219, 220, 220, 219, 220, 220, 221, 222, 221, 223,
    222, 223, 224, 224, 223, 225, 225, 226, 225, 226, 227, 229, 229, 229, 229, 230, 231, 232, 232, 234, 233, 235, 234,
    235, 235, 235, 235, 236, 236, 237, 236, 238, 238, 238, 239, 239, 239, 241, 242, 242, 243, 244, 244, 243, 243, 243,
    244, 245, 243, 243, 245, 245, 246, 247, 246, 247, 247, 246, 244, 245, 246, 246, 246, 246, 247, 246, 247, 247, 247,
    247, 247, 247, 247, 247, 207, 207, 212, 212, 242, 213, 207, 208, 207, 207, 208, 209, 210, 210, 210, 211, 211, 210,
    211, 211, 211, 212, 212, 212, 212, 212, 212, 211, 212, 213, 213, 214, 214, 214, 215, 215, 215, 217, 217, 217, 217,
    218, 218, 218, 219, 219, 220, 220, 220, 220, 221, 222, 222, 222, 224, 224, 224, 224, 224, 224, 225, 225, 227, 227,
    227, 228, 229, 229, 229, 230, 230, 231, 232, 233, 234, 234, 235, 236, 235, 236, 236, 236, 237, 237, 237, 238, 238,
    239, 239, 239, 240, 241, 242, 242, 243, 244, 243, 243, 243, 244, 245, 244, 244, 243, 245, 246, 247, 246, 246, 246,
    247, 246, 244, 245, 246, 246, 246, 246, 246, 246, 247, 247, 247, 247, 247, 247, 247, 247, 207, 211, 207, 223, 247,
    235, 205, 208, 207, 209, 209, 209, 210, 210, 209, 211, 210, 212, 210, 211, 211, 211, 212, 212, 212, 212, 212, 212,
    213, 213, 213, 214, 214, 214, 214, 215, 215, 217, 217, 217, 218, 218, 218, 219, 219, 219, 219, 220, 220, 221, 221,
    221, 223, 222, 223, 223, 224, 224, 224, 224, 226, 226, 227, 227, 228, 228, 229, 229, 229, 230, 231, 232, 232, 233,
    234, 235, 234, 236, 235, 235, 236, 236, 238, 237, 238, 238, 238, 239, 239, 239, 239, 241, 243, 242, 243, 243, 243,
    244, 243, 244, 243, 243, 243, 244, 244, 247, 247, 247, 245, 244, 245, 245, 245, 245, 246, 245, 246, 246, 246, 246,
    247, 247, 247, 247, 247, 247, 246, 247, 207, 215, 219, 231, 247, 244, 204, 207, 207, 209, 208, 210, 209, 210, 212,
    211, 210, 211, 211, 211, 211, 211, 212, 212, 212, 212, 212, 212, 213, 213, 213, 214, 213, 214, 215, 215, 215, 217,
    218, 217, 218, 218, 218, 218, 219, 219, 220, 220, 220, 220, 221, 221, 222, 223, 222, 222, 224, 225, 225, 225, 225,
    226, 227, 228, 228, 229, 229, 229, 230, 231, 232, 232, 231, 232, 232, 233, 235, 234, 236, 235, 236, 236, 237, 236,
    238, 238, 239, 239, 239, 240, 240, 241, 242, 242, 242, 243, 244, 243, 244, 243, 244, 244, 243, 243, 244, 246, 247,
    247, 245, 245, 245, 245, 244, 246, 245, 246, 246, 246, 246, 246, 246, 247, 247, 247, 247, 247, 247, 247, 209, 215,
    216, 216, 239, 245, 207, 207, 208, 209, 210, 210, 210, 210, 210, 210, 210, 210, 210, 211, 212, 211, 212, 212, 212,
    212, 212, 212, 212, 213, 213, 213, 215, 215, 215, 214, 216, 216, 218, 217, 217, 218, 218, 219, 218, 220, 219, 220,
    220, 221, 220, 221, 221, 223, 222, 223, 224, 225, 224, 225, 225, 226, 226, 228, 228, 229, 229, 230, 229, 231, 230,
    231, 232, 231, 233, 234, 234, 234, 234, 235, 236, 237, 237, 237, 238, 238, 239, 239, 239, 240, 240, 242, 243, 242,
    242, 243, 243, 244, 242, 242, 242, 244, 244, 244, 245, 246, 246, 247, 247, 246, 246, 244, 245, 246, 246, 245, 246,
    246, 246, 247, 246, 247, 247, 247, 247, 247, 246, 247, 210, 210, 228, 213, 223, 239, 214, 207, 209, 209, 210, 209,
    210, 210, 212, 210, 210, 212, 211, 212, 211, 212, 211, 212, 212, 212, 212, 212, 213, 213, 213, 214, 214, 215, 215,
    216, 216, 217, 217, 218, 218, 218, 218, 218, 219, 219, 220, 220, 220, 221, 221, 221, 221, 223, 222, 223, 224, 225,
    224, 226, 225, 227, 227, 227, 228, 230, 229, 230, 230, 231, 231, 232, 231, 232, 233, 233, 234, 235, 234, 236, 235,
    236, 236, 237, 237, 238, 240, 238, 239, 238, 239, 242, 242, 243, 243, 243, 242, 242, 243, 243, 242, 244, 244, 244,
    244, 246, 246, 246, 247, 246, 246, 244, 245, 244, 246, 245, 245, 246, 247, 246, 247, 247, 247, 247, 247, 247, 247,
    247, 212, 210, 226, 218, 213, 220, 213, 208, 209, 209, 209, 210, 210, 210, 210, 211, 210, 210, 210, 211, 212, 211,
    212, 211, 213, 213, 212, 213, 213, 213, 213, 214, 214, 215, 215, 216, 217, 218, 217, 218, 218, 218, 218, 219, 219,
    218, 219, 220, 220, 221, 221, 222, 221, 223, 222, 223, 224, 224, 225, 225, 225, 227, 226, 228, 229, 229, 230, 229,
    230, 231, 231, 232, 232, 232, 233, 233, 234, 234, 234, 236, 236, 236, 236, 237, 237, 238, 239, 239, 239, 238, 239,
    242, 243, 243, 244, 242, 243, 242, 242, 242, 242, 242, 245, 244, 244, 244, 245, 245, 245, 245, 245, 244, 245, 245,
    245, 246, 246, 246, 247, 246, 247, 247, 247, 247, 247, 247, 247, 248, 210, 208, 209, 213, 210, 216, 213, 211, 209,
    209, 209, 210, 210, 212, 210, 210, 210, 210, 212, 211, 212, 210, 212, 212, 212, 212, 213, 213, 213, 213, 214, 214,
    214, 215, 214, 216, 215, 218, 217, 218, 218, 218, 218, 219, 219, 219, 220, 220, 220, 220, 220, 222, 221, 223, 222,
    223, 223, 224, 224, 224, 225, 226, 227, 227, 229, 230, 230, 230, 230, 229, 231, 231, 232, 232, 233, 233, 235, 235,
    234, 235, 236, 236, 236, 238, 238, 238, 238, 238, 239, 238, 239, 241, 243, 243, 242, 242, 243, 242, 242, 242, 242,
    243, 245, 246, 244, 243, 243, 244, 245, 245, 245, 245, 245, 245, 246, 246, 246, 246, 246, 247, 247, 246, 247, 247,
    247, 247, 247, 247, 209, 209, 208, 210, 209, 209, 212, 211, 209, 209, 210, 210, 210, 210, 210, 212, 210, 210, 211,
    212, 212, 212, 212, 212, 212, 212, 212, 213, 213, 214, 214, 215, 214, 215, 215, 217, 217, 217, 218, 218, 218, 218,
    218, 219, 219, 219, 219, 220, 220, 220, 220, 222, 221, 222, 222, 224, 224, 223, 225, 225, 225, 226, 227, 228, 229,
    229, 229, 230, 229, 230, 231, 230, 232, 232, 233, 234, 234, 235, 235, 235, 236, 236, 236, 237, 237, 238, 238, 239,
    239, 238, 240, 240, 242, 243, 242, 243, 243, 242, 242, 242, 242, 244, 244, 243, 244, 244, 244, 244, 243, 245, 245,
    245, 244, 245, 246, 246, 246, 246, 246, 247, 247, 247, 247, 247, 247, 247, 247, 247, 209, 209, 208, 209, 209, 209,
    212, 212, 210, 212, 209, 210, 210, 212, 211, 211, 210, 211, 210, 211, 210, 212, 211, 212, 212, 212, 212, 213, 214,
    214, 215, 214, 215, 214, 215, 216, 215, 217, 217, 218, 218, 218, 218, 219, 219, 219, 220, 220, 220, 221, 221, 221,
    221, 223, 222, 223, 223, 224, 225, 225, 225, 226, 227, 227, 229, 229, 230, 230, 230, 230, 231, 230, 232, 233, 233,
    233, 235, 234, 235, 235, 236, 235, 236, 236, 237, 237, 238, 238, 238, 239, 239, 239, 242, 242, 241, 242, 242, 242,
    242, 242, 242, 244, 244, 244, 244, 244, 244, 244, 244, 244, 245, 245, 245, 246, 246, 246, 246, 246, 246, 247, 247,
    247, 247, 247, 247, 247, 247, 247, 210, 209, 209, 210, 209, 212, 216, 220, 209, 210, 209, 210, 210, 210, 211, 211,
    210, 210, 210, 212, 211, 212, 212, 212, 212, 212, 213, 213, 214, 214, 213, 214, 214, 215, 215, 216, 216, 217, 217,
    218, 218, 218, 218, 219, 219, 219, 219, 220, 220, 221, 221, 221, 221, 223, 222, 223, 223, 224, 225, 225, 224, 226,
    226, 227, 228, 228, 229, 229, 230, 231, 231, 231, 232, 232, 232, 233, 235, 234, 235, 235, 236, 235, 236, 236, 236,
    237, 237, 238, 238, 239, 239, 239, 241, 240, 242, 242, 242, 242, 242, 242, 242, 244, 244, 244, 244, 244, 244, 244,
    244, 243, 245, 245, 244, 245, 246, 246, 246, 247, 246, 247, 247, 247, 246, 247, 247, 247, 247, 248, 210, 210, 209,
    209, 209, 210, 210, 216, 212, 210, 210, 211, 210, 211, 211, 211, 212, 211, 210, 211, 212, 212, 212, 212, 212, 213,
    213, 213, 214, 214, 214, 215, 215, 214, 215, 217, 215, 217, 217, 217, 218, 218, 218, 219, 220, 219, 220, 219, 221,
    221, 221, 221, 222, 222, 223, 223, 223, 224, 224, 225, 226, 225, 227, 226, 227, 229, 229, 229, 230, 230, 230, 231,
    231, 232, 232, 233, 235, 234, 234, 236, 236, 236, 236, 236, 238, 237, 238, 238, 238, 239, 239, 239, 239, 240, 241,
    241, 241, 242, 242, 242, 242, 243, 244, 244, 244, 244, 244, 244, 244, 243, 245, 245, 244, 244, 245, 246, 246, 247,
    246, 246, 247, 246, 246, 247, 247, 247, 247, 247};
