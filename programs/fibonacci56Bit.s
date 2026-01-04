; r8 is iterations left

; Exit Codes on r0:
; 0x0: Program ran fine
; 0x1: Overflow (out of bits)

    LDI r8, 255
    INC r7
loop:
    SUBI r8, 0x1
    BLO finishedRight
    ADD r7, r15
    ADC r6, r14
    ADC r5, r13
    ADC r4, r12
    ADC r3, r11
    ADC r2, r10
    ADC r1, r9
    BCS overflowLeft
    SUBI r8, 0x1
    BLO finishedLeft
    ADD r15, r7
    ADC r14, r6
    ADC r13, r5
    ADC r12, r4
    ADC r11, r3
    ADC r10, r2
    ADC r9, r1
    BCS overflowRight
    JMP loop

overflowLeft:
    LDI r0, 0x1
    JMP copyRight
overflowRight:
    LDI r0, 0x1
    JMP clearRight

finishedLeft:
    JMP clearRight
finishedRight:
    JMP copyRight

copyRight:
    MOV r1, r9
    MOV r2, r10
    MOV r3, r11
    MOV r4, r12
    MOV r5, r13
    MOV r6, r14
    MOV r7, r15
    JMP clearRight

clearRight:
    LDI r9, 0x0
    LDI r10, 0x0
    LDI r11, 0x0
    LDI r12, 0x0
    LDI r13, 0x0
    LDI r14, 0x0
    LDI r15, 0x0
    SUBI r8, 0xff
    HLT
    