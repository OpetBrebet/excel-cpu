import sys
import re
import csv
import math

# Instruction Set Architecture Definition
ISA = {
    # Basic Operations
    'NOP':  {'opcode': '0000000000000000', 'format': 'none'},
    'HLT':  {'opcode': '0000000000000001', 'format': 'none'},
    
    # Register Operations
    'MOV':  {'opcode': '0001ddddssss0000', 'format': 'reg_reg'},
    'CMP':  {'opcode': '0001ddddssss0001', 'format': 'reg_reg'},
    'PUSH': {'opcode': '0001ssss00000010', 'format': 'reg'},
    'POP':  {'opcode': '0001dddd00000011', 'format': 'reg'},
    'IN':   {'opcode': '0001ddddiiii0100', 'format': 'reg_imm4'},
    'OUT':  {'opcode': '0001ssssiiii0101', 'format': 'reg_imm4'},
    
    # Arithmetic/Logic Operations
    'NOT':  {'opcode': '0010ddddssss0000', 'format': 'reg_reg'},
    'NEG':  {'opcode': '0010ddddssss0001', 'format': 'reg_reg'},
    'INC':  {'opcode': '0010dddd00000010', 'format': 'reg'},
    'DEC':  {'opcode': '0010dddd00000011', 'format': 'reg'},
    'SHL':  {'opcode': '0010dddd00000100', 'format': 'reg'},
    'SHR':  {'opcode': '0010dddd00000101', 'format': 'reg'},
    'ROL':  {'opcode': '0010dddd00000110', 'format': 'reg'},
    'ROR':  {'opcode': '0010dddd00000111', 'format': 'reg'},
    'ASR':  {'opcode': '0010dddd00001000', 'format': 'reg'},
    'ADD':  {'opcode': '0010ddddssss1001', 'format': 'reg_reg'},
    'SUB':  {'opcode': '0010ddddssss1010', 'format': 'reg_reg'},
    'ADC':  {'opcode': '0010ddddssss1011', 'format': 'reg_reg'},
    'SUBC': {'opcode': '0010ddddssss1100', 'format': 'reg_reg'},
    'AND':  {'opcode': '0010ddddssss1101', 'format': 'reg_reg'},
    'OR':   {'opcode': '0010ddddssss1110', 'format': 'reg_reg'},
    'XOR':  {'opcode': '0010ddddssss1111', 'format': 'reg_reg'},
    
    # Jump Operations
    'JMP':  {'opcode': '0100pppppppppppp', 'format': 'addr12'},
    'CALL': {'opcode': '0101pppppppppppp', 'format': 'addr12'},
    'RET':  {'opcode': '0110000000000000', 'format': 'none'},
    'RETI':  {'opcode': '0110000000000001', 'format': 'none'},
    'RJMP': {'opcode': '01100010oooooooo', 'format': 'offset8'},
    'RCALL':{'opcode': '01100011oooooooo', 'format': 'offset8'},
    
    # Branch Operations
    'BNQ':  {'opcode': '01110000oooooooo', 'format': 'offset8'},
    'BEQ':  {'opcode': '01110001oooooooo', 'format': 'offset8'},
    'BCC':  {'opcode': '01110010oooooooo', 'format': 'offset8'},
    'BLO':  {'opcode': '01110010oooooooo', 'format': 'offset8'},  # Same as BCC
    'BCS':  {'opcode': '01110011oooooooo', 'format': 'offset8'},
    'BHS':  {'opcode': '01110011oooooooo', 'format': 'offset8'},  # Same as BCS
    'BPO':  {'opcode': '01110100oooooooo', 'format': 'offset8'},
    'BNE':  {'opcode': '01110101oooooooo', 'format': 'offset8'},  # Negative
    'BVC':  {'opcode': '01110110oooooooo', 'format': 'offset8'},
    'BVS':  {'opcode': '01110111oooooooo', 'format': 'offset8'},
    'BLS':  {'opcode': '01111000oooooooo', 'format': 'offset8'},
    'BHI':  {'opcode': '01111001oooooooo', 'format': 'offset8'},
    'BLT':  {'opcode': '01111010oooooooo', 'format': 'offset8'},
    'BGE':  {'opcode': '01111011oooooooo', 'format': 'offset8'},
    'BLE':  {'opcode': '01111100oooooooo', 'format': 'offset8'},
    'BGT':  {'opcode': '01111101oooooooo', 'format': 'offset8'},
    
    # Immediate Operations
    'LDI':  {'opcode': '1000ddddkkkkkkkk', 'format': 'reg_imm8'},
    'CPI':  {'opcode': '1001sssskkkkkkkk', 'format': 'reg_imm8'},
    'ADI':  {'opcode': '1010ddddkkkkkkkk', 'format': 'reg_imm8'},
    'SUBI': {'opcode': '1011ddddkkkkkkkk', 'format': 'reg_imm8'},
    'ANDI': {'opcode': '1100ddddkkkkkkkk', 'format': 'reg_imm8'},
    'ORI':  {'opcode': '1101ddddkkkkkkkk', 'format': 'reg_imm8'},
    'XORI': {'opcode': '1110ddddkkkkkkkk', 'format': 'reg_imm8'},
    
    # Memory Operations
    'STR':  {'opcode': '1111ssss0rrr0000', 'format': 'reg_regd'},
    'LDR':  {'opcode': '1111dddd0rrr0001', 'format': 'reg_regd'},
    'ST':   {'opcode': '1111ssss00000010', 'format': 'reg_addr12', 'extended': True},
    'LD':   {'opcode': '1111dddd00000011', 'format': 'reg_addr12', 'extended': True},
}

# Argument Types
class ArgumentType:
    def __init__(self, value, arg_type):
        self.value = value
        self.type = arg_type
    
    def __repr__(self):
        return f"{self.type}({self.value})"

class Register(ArgumentType):
    def __init__(self, value):
        super().__init__(value, "REGISTER")
        self.reg_num = int(value[1:])  # Extract number from r0, r1, r2, etc.
        if self.reg_num < 0 or self.reg_num > 15:
            raise ValueError(f"Register number must be 0-15, got: {self.reg_num}")
    
    def toBin(self, bits=4):
        return format(self.reg_num, f'0{bits}b')

class Immediate(ArgumentType):
    def __init__(self, value):
        super().__init__(value, "IMMEDIATE")
        if value.startswith('0x') or value.startswith('0X'):
            self.num_value = int(value, 16)
        elif value.startswith('0b') or value.startswith('0B'):
            self.num_value = int(value, 2)
        else:
            self.num_value = int(value)
    
    def toBin(self, bits=8):
        if self.num_value < 0:
            # Two's complement for negative numbers
            return format((1 << bits) + self.num_value, f'0{bits}b')
        return format(self.num_value, f'0{bits}b')

class Label(ArgumentType):
    def __init__(self, value):
        super().__init__(value, "LABEL")
        self.resolved_address = None
    
    def resolve(self, address):
        self.resolved_address = address
    
    def toBin(self, bits=12):
        if self.resolved_address is None:
            raise ValueError(f"Label {self.value} not resolved")
        return format(self.resolved_address, f'0{bits}b')
    
    def getOffset(self, current_pc, bits=8):
        """Calculate relative offset for branch instructions"""
        if self.resolved_address is None:
            raise ValueError(f"Label {self.value} not resolved")
        offset = self.resolved_address - (current_pc + 1)
        if offset < -(1 << (bits-1)) or offset >= (1 << (bits-1)):
            raise ValueError(f"Branch offset {offset} out of range for {bits}-bit signed offset")
        if offset < 0:
            return format((1 << bits) + offset, f'0{bits}b')
        return format(offset, f'0{bits}b')

class Instruction:
    def __init__(self, opcode, args, line_num):
        self.opcode = opcode
        self.args = args
        self.line_num = line_num
        self.address = None
    
    def __repr__(self):
        return f"{self.opcode} {', '.join(str(arg) for arg in self.args)}"
    
    def toBinary(self):
        """Generate binary code for this instruction"""
        if self.opcode not in ISA:
            raise ValueError(f"Unknown instruction: {self.opcode}")
        
        instr_info = ISA[self.opcode]
        template = instr_info['opcode']
        format_type = instr_info['format']
        
        # Start with the template
        binary = template
        
        if format_type == 'none':
            pass  # No arguments to substitute
        
        elif format_type == 'reg':
            if len(self.args) != 1 or not isinstance(self.args[0], Register):
                raise ValueError(f"{self.opcode} requires 1 register argument")
            reg_bits = self.args[0].toBin(4)
            if 'dddd' in binary:
                binary = binary.replace('dddd', reg_bits)
            elif 'ssss' in binary:
                binary = binary.replace('ssss', reg_bits)
        
        elif format_type == 'reg_reg':
            if len(self.args) != 2:
                raise ValueError(f"{self.opcode} requires 2 arguments")
            if not isinstance(self.args[0], Register) or not isinstance(self.args[1], Register):
                raise ValueError(f"{self.opcode} requires register arguments")
            dest_bits = self.args[0].toBin(4)
            src_bits = self.args[1].toBin(4)
            binary = binary.replace('dddd', dest_bits).replace('ssss', src_bits)
        
        elif format_type == 'reg_imm4':
            if len(self.args) != 2:
                raise ValueError(f"{self.opcode} requires 2 arguments")
            if not isinstance(self.args[0], Register):
                raise ValueError(f"{self.opcode} requires register as first argument")
            if not isinstance(self.args[1], Immediate):
                raise ValueError(f"{self.opcode} requires immediate as second argument")
            reg_bits = self.args[0].toBin(4)
            imm_bits = self.args[1].toBin(4)  # 4-bit immediate
            if 'dddd' in binary:
                binary = binary.replace('dddd', reg_bits)
            elif 'ssss' in binary:
                binary = binary.replace('ssss', reg_bits)
            binary = binary.replace('iiii', imm_bits)

        elif format_type == 'reg_imm8':
            if len(self.args) != 2:
                raise ValueError(f"{self.opcode} requires 2 arguments")
            if not isinstance(self.args[0], Register):
                raise ValueError(f"{self.opcode} requires register as first argument")
            if not isinstance(self.args[1], Immediate):
                raise ValueError(f"{self.opcode} requires immediate as second argument")
            reg_bits = self.args[0].toBin(4)
            imm_bits = self.args[1].toBin(8)
            if 'dddd' in binary:
                binary = binary.replace('dddd', reg_bits)
            elif 'ssss' in binary:
                binary = binary.replace('ssss', reg_bits)
            binary = binary.replace('kkkkkkkk', imm_bits)
        
        elif format_type == 'addr12':
            if len(self.args) != 1:
                raise ValueError(f"{self.opcode} requires 1 address argument")
            if isinstance(self.args[0], Label):
                addr_bits = self.args[0].toBin(12)
            elif isinstance(self.args[0], Immediate):
                addr_bits = self.args[0].toBin(12)
            else:
                raise ValueError(f"{self.opcode} requires address or label")
            binary = binary.replace('pppppppppppp', addr_bits)
        
        elif format_type == 'offset8':
            if len(self.args) != 1:
                raise ValueError(f"{self.opcode} requires 1 offset argument")
            if isinstance(self.args[0], Label):
                offset_bits = self.args[0].getOffset(self.address, 8)
            elif isinstance(self.args[0], Immediate):
                offset_bits = self.args[0].toBin(8)
            else:
                raise ValueError(f"{self.opcode} requires offset or label")
            binary = binary.replace('oooooooo', offset_bits)
        
        elif format_type == 'reg_regd':
            if len(self.args) != 2:
                raise ValueError(f"{self.opcode} requires 2 arguments")
            if not isinstance(self.args[0], Register):
                raise ValueError(f"{self.opcode} requires register as first argument")
            if not isinstance(self.args[1], Immediate):
                raise ValueError(f"{self.opcode} requires pointer register as second argument")
            reg_bits = self.args[0].toBin(4)
            regd_bits = self.args[1].toBin(3)
            if 'dddd' in binary:
                binary = binary.replace('dddd', reg_bits)
            elif 'ssss' in binary:
                binary = binary.replace('ssss', reg_bits)
            binary = binary.replace('rrr', regd_bits)
        
        # Handle extended instructions (16-bit + 12-bit address)
        if instr_info.get('extended', False):
            if len(self.args) != 2:
                raise ValueError(f"{self.opcode} requires 2 arguments")
            reg_bits = self.args[0].toBin(4)
            if 'dddd' in binary:
                binary = binary.replace('dddd', reg_bits)
            elif 'ssss' in binary:
                binary = binary.replace('ssss', reg_bits)
            
            # Return both instruction word and address word
            if isinstance(self.args[1], Label):
                addr_bits = self.args[1].toBin(12)
            elif isinstance(self.args[1], Immediate):
                addr_bits = self.args[1].toBin(12)
            else:
                raise ValueError(f"{self.opcode} requires address argument")
            
            return [binary, '0000' + addr_bits]  # 12-bit address padded to 16 bits
        
        return [binary]

def parse_argument(arg_str):
    """Parse a single argument and return appropriate type"""
    arg_str = arg_str.strip()
    
    # Register (r0, r1, r2, etc.) - case insensitive
    if re.match(r'^[rR]\d+$', arg_str):
        return Register(arg_str.lower())  # Normalize to lowercase
    
    # Label (starts with underscore or letter)
    elif re.match(r'^[_a-zA-Z][_a-zA-Z0-9]*$', arg_str):
        return Label(arg_str)
    
    # Immediate value (number, hex, binary)
    elif re.match(r'^-?\d+$|^0[xX][0-9a-fA-F]+$|^0[bB][01]+$', arg_str):
        return Immediate(arg_str)
    
    else:
        raise ValueError(f"Unknown argument type: {arg_str}")

def strip_inline_comment(line):
    """Remove inline comments (everything after ; or #) from a line"""
    # Find the first occurrence of ; or #
    comment_pos = -1
    for i, char in enumerate(line):
        if char in [';', '#']:
            comment_pos = i
            break
    
    if comment_pos != -1:
        return line[:comment_pos]
    return line

def parse_assembly_line(line, line_num):
    """Parse a single line and return (type, data) or None"""
    original_line = line
    
    # Remove inline comments first
    line = strip_inline_comment(line)
    stripped = line.strip()
    
    # Skip empty lines and comments
    if not stripped:
        return None
    
    # Check for .org directive (must be lowercase with dot)
    if stripped.startswith('.org'):
        parts = stripped.split()
        if len(parts) != 2:
            raise ValueError(f".org directive requires exactly one argument at line {line_num}")
        address_str = parts[1]
        # Parse the address (support hex, binary, decimal)
        if address_str.startswith('0x') or address_str.startswith('0X'):
            address = int(address_str, 16)
        elif address_str.startswith('0b') or address_str.startswith('0B'):
            address = int(address_str, 2)
        else:
            address = int(address_str)
        return ('ORG', address)
    
    # Check if it's a label (ends with : and not indented)
    if stripped.endswith(':') and not original_line.startswith(('\t', ' ')):
        label_name = stripped[:-1]
        return ('LABEL', label_name)
    
    # Check if it's an instruction (indented with tab or spaces OR not a label)
    if original_line.startswith(('\t', ' ')) or not stripped.endswith(':'):
        instruction_text = stripped
        
        # Handle comma-separated arguments
        if ',' in instruction_text:
            parts = [part.strip() for part in instruction_text.split(',')]
            first_parts = parts[0].split()
            opcode = first_parts[0].upper()
            args = []
            
            if len(first_parts) > 1:
                args.append(first_parts[1])
            args.extend(parts[1:])
        else:
            parts = instruction_text.split()
            opcode = parts[0].upper()
            args = parts[1:] if len(parts) > 1 else []
        
        # Parse each argument
        parsed_args = []
        for arg in args:
            if arg:
                parsed_args.append(parse_argument(arg))
        
        return ('INSTRUCTION', opcode, parsed_args, line_num)
    
    return None

def parse_assembly(filename):
    labels = {}
    instructions = []
    instruction_count = 4  # Start after ISR vectors (0x0-0x3)
    
    with open(filename, 'r') as file:
        lines = file.readlines()
    
    print(f"Processing {len(lines)} lines...")
    
    # First pass: collect labels and instructions
    for line_num, line in enumerate(lines, 1):
        print(f"Line {line_num}: '{line.rstrip()}'")
        
        result = parse_assembly_line(line, line_num)
        
        if result is None:
            print(f"  -> Skipped (empty/comment)")
            continue
        
        if result[0] == 'ORG':
            address = result[1]
            instruction_count = address
            print(f"  -> .org directive: setting address to 0x{address:04X}")
        
        elif result[0] == 'LABEL':
            label_name = result[1]
            labels[label_name] = instruction_count
            print(f"  -> Label '{label_name}' at address 0x{instruction_count:04X}")
        
        elif result[0] == 'INSTRUCTION':
            opcode, args, line_num = result[1], result[2], result[3]
            instruction = Instruction(opcode, args, line_num)
            instruction.address = instruction_count
            instructions.append(instruction)
            print(f"  -> Instruction 0x{instruction_count:04X}: {instruction}")
            instruction_count += 1
            
            # Handle extended instructions (take 2 words)
            if opcode in ISA and ISA[opcode].get('extended', False):
                instruction_count += 1
    
    # Second pass: resolve label addresses
    for instruction in instructions:
        for arg in instruction.args:
            if isinstance(arg, Label):
                if arg.value in labels:
                    arg.resolve(labels[arg.value])
                else:
                    raise ValueError(f"Undefined label: {arg.value} at line {instruction.line_num}")
    
    return instructions, labels

def generate_binary(instructions):
    """Generate binary output with proper addressing"""
    binary_output = {}  # Use dictionary to handle sparse addressing
    
    # Initialize ISR vectors (0x0 to 0x3) with RETI instruction
    reti_opcode = ISA['RETI']['opcode']
    for addr in range(0, 4):
        binary_output[addr] = reti_opcode
    
    # Now add user instructions, which will override RETI if .org is used
    for instruction in instructions:
        try:
            binary_words = instruction.toBinary()
            address = instruction.address
            for i, word in enumerate(binary_words):
                binary_output[address + i] = word
        except Exception as e:
            raise ValueError(f"Error generating binary for {instruction} at line {instruction.line_num}: {e}")
    
    return binary_output

def write_csv_output(binary_dict, filename):
    """Write binary code to CSV file with exactly 256 rows, each with 256 bits.
    Takes a dictionary of address->binary_word mapping."""

    all_bits = ['0'] * (256 * 256)  # Initialize with all zeros
    
    # Place instructions at their proper addresses
    for address, binary_word in sorted(binary_dict.items()):
        bit_position = address * 16  # Each instruction is 16 bits
        if bit_position + 16 <= len(all_bits):
            for i, bit in enumerate(binary_word):
                all_bits[bit_position + i] = bit
    
    # Split into 256 rows of 256 bits
    all_rows = []
    for i in range(256):
        row = all_bits[i * 256 : (i + 1) * 256]
        all_rows.append(row)

    # Write to CSV
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=';')
        for row in all_rows:
            writer.writerow(row)
    
    print(f"CSV output written to {filename} (256 columns, {len(binary_dict)} instructions)")

# Main execution
if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python assembler.py <assembly_file> [output_csv]")
        print("  If output_csv is not specified, defaults to ./ROM.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    csv_filename = sys.argv[2] if len(sys.argv) == 3 else './ROM.csv'

    try:
        instructions, labels = parse_assembly(input_file)
        
        print("\n=== PARSED INSTRUCTIONS ===")
        for instr in instructions:
            print(f"0x{instr.address:04X}: {instr}")
        
        print("\n=== LABELS ===")
        for label, addr in sorted(labels.items()):
            print(f"{label}: 0x{addr:04X}")
        
        print("\n=== BINARY OUTPUT ===")
        binary_dict = generate_binary(instructions)
        
        for address in sorted(binary_dict.keys()):
            binary = binary_dict[address]
            hex_val = hex(int(binary, 2))[2:].upper().zfill(4)
            print(f"Address 0x{address:04X}: {binary} (0x{hex_val})")
        
        # Write to CSV file (256 columns, one bit per cell)
        write_csv_output(binary_dict, csv_filename)
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)