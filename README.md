# Excel CPU

An educational CPU designed and implemented entirely in **Microsoft Excel**.

## Overview

This project is a fully custom 8-bit CPU simulated with Excel. The CPU models registers, memory, flags, and control logic using spreadsheet formulas, with each Excel cell representing a single bit. Instructions are executed through a control system that allows arithmetic, logic, branching, stack operations, interrupts, and I/O, which is crucial to learn how real CPUs work internally.

## Features

* Basic arithmetic like addition, bitwise operations (AND, OR, XOR), bit shifts, and rotations
* 16 general-purpose registers and 16 I/O registers
* 12 Bits of Memory Address (4 KiB of addressable memory)
* 12 Bits of Instruction Address (up to 4096 instructions)
* A growing down stack which is 256 Bytes long
* Interrupts! You can add a timer or other hardware
* Jumps and calls, with being able to return from a call
* Branches with specific conditions from the CPU Flags

## Instruction Set Architecture

<img src="./assets/InstructionSetArchitecture.png" alt="Image of the ISA">

See the full spreadsheet [here](https://docs.google.com/spreadsheets/d/1iYksSgQVaDx2x8g_rPeAjbsAa2NUGommz_33XeF8mEM/edit)

## How to Use

Open the CPU.xlsx file. Disable Reset and enable the Clock, then hold F9 to keep refreshing the clock.

## Assembling a program

The program currently inside the CPU is just a single program and a basic one. You will need Python to assemble programs.

To use another program:

* Execute `py ASMbler.py ./programs/<program_name>`, or write your own program!
* This will write `ROM.csv`
* To make Excel read the new program, press `F9` first so Excel is able to find the ROM file
* Go to the `Data` tab and click `Refresh All`, which refreshes the `ROM` inside the Excel Workbook.
* Start the CPU!

## Limitations

* Slow execution speed (approximately 20 Hz maximum clock)
* Unstable behavior due to Excel's recalculation quirks
* No floating-point support
