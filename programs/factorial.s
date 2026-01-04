; r14 for the multiplication's addition interation
; r15 for the current multiplication

.org 0x04
main:
    LDI r15, 0x0a
    MOV r7, r15
    DEC r15
    BEQ stop
    MOV r14, r15
    CALL mult_loop
    CALL copy_registers
    DEC r15
    JMP fac_loop

fac_loop:
    DEC r15
    BEQ stop
    MOV r14, r15
    CALL mult_loop
    CALL copy_registers
    JMP fac_loop

copy_registers:
    MOV r7, r3
    MOV r6, r2
    MOV r5, r1
    MOV r4, r0
    RET

mult_loop:
    ADD r3, r7
    ADC r2, r6
    ADC r1, r5
    ADC r0, r4
    DEC r14
    BNQ mult_loop
    RET

stop:
    HLT

