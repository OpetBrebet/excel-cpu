main:
    XOR r15, r15
writeloop:
    STR r15, 0b111
    ADI r15, 1
    ADC r14, r0
    JMP writeloop