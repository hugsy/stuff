#
# IDA Python Processor for HSVM v1.4
# Haxathon CTF 2012
# by @_hugsy_
#
# instructions/opcode from hsvm1.4/src/instruction.h
# instructions details from hsvm1.4/README
#
# scheme
#
# 0-7            8-15           16-23           24-31          Encoding Name
# |--------------|--------------|--------------|--------------|
# | OPCODE       |              |              |              | Encoding-A
# |--------------|--------------|--------------|--------------|
# | OPCODE       | REGISTER-A   |              |              | Encoding-B
# |--------------|--------------|--------------|--------------|
# | OPCODE       | REGISTER-A   | REGISTER-B   |              | Encoding-C
# |--------------|--------------|--------------|--------------|
# | OPCODE       | REGISTER-A   | REGISTER-B   | REGISTER-C   | Encoding-D
# |--------------|--------------|--------------|--------------|
# | OPCODE       | REGISTER-A   | LVAL                        | Encoding-E
# |--------------|--------------|--------------|--------------|
# | OPCODE       |              | LVAL                        | Encoding-F
# |--------------|--------------|--------------|--------------|
#

import sys
from idaapi import *

version = '1.0'

LITTLE_ENDIAN = 0
BIG_ENDIAN = 1

class hsvm_processor_t(processor_t):
	id = 0x31337
	flag = PR_ASSEMBLE | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_USE32
	cnbits = 8
	dnbits = 8

	psnames = ['hsvm']
	plnames = ['HSVM Processor']

	segreg_size = 0
	instruc_start = 0

	tbyte_size = 0

	assembler = {
		'flag' : PR_USE32 | PRN_HEX | PR_RNAMESOK,
		'uflag' : 0,
		'name': "HSVM bytecode assembler",
		'origin': "org",
		'end': "end",

		'cmnt': ";",

                'ascsep': "\"",
                'accsep': "'",
                'esccodes': "\"'",

		'a_ascii': "db",
		'a_byte': "db",
		'a_word': "dw",
		'a_dword': "dd",
		'a_qword': "dq",
		# 'a_oword': "xmmword",
		'a_float': "dd",
		'a_double': "dq",
		# 'a_tbyte': "dt",

		# sequences may appear:
		#		#h - header
		#		#d - size
		#		#v - value
		#		#s(b,w,l,q,f,d,o) - size specifiers
		#                                   for byte,word,dword,qword,float,double,oword
		'a_dups': "#d dup(#v)",
		'a_bss': "%s dup ?",
		'a_seg': "seg",
		'a_curip': "$",
		'a_public': "public",
		'a_weak': "weak",
		'a_extrn': "extrn",
		'a_comdef': "",
		'a_align': "align",

		'lbrace': "(",
		'rbrace': ")",

		'a_mod': "%",
		'a_band': "&",
		'a_bor': "|",
		'a_xor': "^",
		'a_bnot': "~",
		'a_shl': "<<",
		'a_shr': ">>",

		'a_sizeof_fmt': "size %s",
	} # Assembler

	#
	# Some internal flags used by the decoder, emulator and output
	# useless
	FL_B				 = 0x000000001 # 8 bits
	FL_W				 = 0x000000002 # 16 bits
	FL_D				 = 0x000000004 # 32 bits
	FL_Q				 = 0x000000008 # 64 bits
	FL_OP1			     	 = 0x000000010 # check operand 1
	FL_32		 		 = 0x000000020 # Is 32
	FL_64				 = 0x000000040 # Is 64
	FL_NATIVE			 = 0x000000080 # native call
	FL_REL				 = 0x000000100 # relative address
	FL_CS				 = 0x000000200 # Condition flag is set
	FL_NCS				 = 0x000000400 # Condition flag is not set
	FL_INDIRECT			 = 0x000000800 # This is an indirect access (not immediate value)
	FL_SIGNED			 = 0x000001000 # This is a signed operand


	def __init__(self):
		idaapi.processor_t.__init__(self)
		self.PTRSZ = 4
		self.init_constants()
		self.init_instructions()
		self.init_registers()

	def notify_init(self, idp_file):
		cvar.inf.mf = BIG_ENDIAN
		cvar.inf.wide_high_byte_first = True
		return True

	def init_constants(self):
		#
		# Register instruction specific flags
		# useless

		# self.OP_FLAG_REG_REG                   = 0x00
		# self.OP_FLAG_REG_DIRECT08              = 0x01
		# self.OP_FLAG_REG_DIRECT16              = 0x02
		# self.OP_FLAG_REG                       = 0x03
		# self.OP_FLAG_DIRECT16                  = 0x04
		# self.OP_FLAG_DIRECT08                  = 0x05
		# self.OP_FLAG_REGINDIRECT_REG           = 0x06
		# self.OP_FLAG_REGINDIRECT_DIRECT08      = 0x07
		# self.OP_FLAG_REGINDIRECT_DIRECT16      = 0x08
		# self.OP_FLAG_REGINDIRECT_REGINDIRECT   = 0x09
		# self.OP_FLAG_REG_REGINDIRECT           = 0x0a

		#
		# Syscall table
		#
		self.syscall_table = {
			0x00: "SYS_OPEN",
			0x01: "SYS_READ",
			0x02: "SYS_WRITE",
			0x03: "SYS_CLOSE",
		}

	def init_instructions(self):
		class idef:
			def __init__(self, name, cf, d):
				self.name = name
				self.cf	= cf
				self.d	 = d

		arithmetic_flags = CF_CHG1 | CF_USE2 | CF_USE3
		arithmetic_lval_flags = CF_USE1 | CF_USE2
		#
		# Instructions table (w/ pointer to decoder)
		#
		self.itable = {

			# arithmethic instructions
			0x10: idef(name='ADD',		d=self.decode_ADD, cf = arithmetic_flags),
			0x11: idef(name='ADDLVAL',	d=self.decode_ADDLVAL, cf = arithmetic_lval_flags),
			0x12: idef(name='SUB',		d=self.decode_SUB, cf = arithmetic_flags),
			0x13: idef(name='SUBLVAL',	d=self.decode_SUBLVAL, cf = arithmetic_lval_flags),
			0x14: idef(name='MUL',		d=self.decode_MUL, cf = arithmetic_flags),
			0x15: idef(name='MULLVAL',	d=self.decode_MULLVAL, cf = arithmetic_lval_flags),
			0x16: idef(name='DIV',		d=self.decode_DIV, cf = arithmetic_flags),
			0x17: idef(name='DIVLVAL',	d=self.decode_DIVLVAL, cf = arithmetic_lval_flags),
			0x18: idef(name='MOD',		d=self.decode_MOD, cf = arithmetic_flags),
			0x19: idef(name='MODLVAL',	d=self.decode_MODLVAL, cf = arithmetic_lval_flags),
			0x1a: idef(name='AND',		d=self.decode_AND, cf = arithmetic_flags),
			0x1b: idef(name='ANDLVAL',	d=self.decode_ANDLVAL, cf = arithmetic_lval_flags),
			0x1C: idef(name='OR',		d=self.decode_OR, cf = arithmetic_flags),
			0x1d: idef(name='ORLVAL',	d=self.decode_ORLVAL, cf = arithmetic_lval_flags),
			0x1e: idef(name='XOR',		d=self.decode_XOR, cf = arithmetic_flags),
			0x1f: idef(name='XORLVAL',	d=self.decode_XORLVAL, cf = arithmetic_lval_flags),

			# jumps
			0x20: idef(name='JMP',		d=self.decode_JMP, cf = CF_USE1),
			0x21: idef(name='JE',		d=self.decode_JE, cf = CF_USE1 | CF_JUMP),
			0x22: idef(name='JNE',		d=self.decode_JNE, cf = CF_USE1 | CF_JUMP),
			0x23: idef(name='JL',		d=self.decode_JL, cf = CF_USE1 | CF_JUMP),
			0x24: idef(name='JLE',		d=self.decode_JLE, cf = CF_USE1 | CF_JUMP),
			0x25: idef(name='JG',		d=self.decode_JG, cf = CF_USE1 | CF_JUMP),
			0x26: idef(name='JGE',		d=self.decode_JGE, cf = CF_USE1 | CF_JUMP),

			# function call/ret
			0x27: idef(name='CALL',		d=self.decode_CALL, cf = CF_USE1 | CF_CALL),
			0x28: idef(name='CALLR',        d=self.decode_CALLR, cf = CF_USE1 | CF_CALL),
			0x29: idef(name='RET',		d=self.decode_RET, cf = CF_STOP),

			# load/store
			0x30: idef(name='LOAD',		d=self.decode_LOAD, cf = CF_USE1),
			0x31: idef(name='LOADR',	d=self.decode_LOADR, cf = CF_USE1),
			0x32: idef(name='LOADB',	d=self.decode_LOADB, cf = CF_USE1),
			0x33: idef(name='LOADBR',	d=self.decode_LOADBR, cf = CF_USE1),

			0x34: idef(name='STOR',	        d=self.decode_STOR, cf = CF_USE1),
			0x35: idef(name='STORR',	d=self.decode_STORR, cf = CF_USE1),
			0x36: idef(name='STORB',	d=self.decode_STORB, cf = CF_USE1),
			0x37: idef(name='STORBR',	d=self.decode_STORBR, cf = CF_USE1),

			# stdin/stdout ops
			0x40: idef(name='IN',		d=self.decode_ENCODING_B, cf = CF_CHG1),
			0x41: idef(name='OUT',		d=self.decode_ENCODING_B, cf = CF_USE1),

			# stack
			0x42: idef(name='PUSH',    	d=self.decode_PUSH, cf = CF_USE1),
			0x43: idef(name='PUSHLVAL', 	d=self.decode_PUSHLVAL, cf = CF_USE1),
			0x44: idef(name='POP',		d=self.decode_POP, cf = CF_CHG1),

			# reg affectation
			0x51: idef(name='MOV',		d=self.decode_MOV, cf = CF_USE1 | CF_USE2),
			0x52: idef(name='MOVLVAL',	d=self.decode_MOVLVAL, cf = CF_USE1 | CF_USE2),

			# compare
			0x53: idef(name='CMP',		d=self.decode_CMP, cf = CF_USE1 | CF_USE2),
			0x54: idef(name='CMPLVAL',	d=self.decode_CMPLVAL, cf = CF_USE1 | CF_USE2),

			# misc
			0x60: idef(name='HLT',		d=self.decode_HLT, cf = CF_STOP),
			0x61: idef(name='SYSCALL',	d=self.decode_SYSCALL, cf = 0),
			0x90: idef(name='NOP',		d=self.decode_NOP, cf = 0),
		}

		# Now create an instruction table compatible with IDA processor module requirements
		Instructions = []
		i = 0
		for x in self.itable.values():
			Instructions.append({'name': x.name, 'feature': x.cf})
			setattr(self, 'itype_' + x.name, i)
			i += 1

		# icode of the last instruction + 1
		self.instruc_end = len(Instructions) + 1

		# Array of instructions
		self.instruc = Instructions

		# Icode of return instruction. It is ok to give any of possible return
		# instructions
		self.icode_return = self.itype_RET


	def init_registers(self):
		"""This function parses the register table and creates corresponding ireg_XXX constants"""

		# Registers
		self.regNames = [
			"R0",
			"R1",
			"R2",
			"R3",
			"R4",
			"R5",
			"R6",
			"RIP",
			"RBP",
			"RSP",
			"R7",
			"RCS",
			"RDS",
		]
		# note : rcs and rds are mandatory for ida (rely too much on x86 arch)

		for i in xrange(len(self.regNames)):
			setattr(self, 'ireg_' + self.regNames[i], i)

		self.regFirstSreg = self.regCodeSreg = self.ireg_RCS
		self.regLastSreg = self.regDataSreg = self.ireg_RDS

	#
	# IDA instruction decoders
	#

	# Generic decoders
	def decode_ENCODING_A(self, opbyte):
		#
		# <opcode>
		#
		self.cmd.Op1.type  = o_void

		ua_next_byte()
		ua_next_word()
		return True

	def decode_ENCODING_B(self, opbyte):
		#
		# <opcode> <REG>
		#
		self.cmd.Op1.type = o_reg
		self.cmd.Op1.dtyp = dt_byte
		self.cmd.Op1.reg = ua_next_byte()

		padding = ua_next_word()
		return True

	def decode_ENCODING_C(self, opbyte):
		#
		# <opcode> <REG> <REG>
		#
		self.cmd.Op1.type = o_reg
		self.cmd.Op1.dtyp = dt_byte
		self.cmd.Op1.reg = ua_next_byte()

		self.cmd.Op2.type = o_reg
		self.cmd.Op2.dtyp = dt_byte
		self.cmd.Op2.reg = ua_next_byte()

		padding = ua_next_byte()
		return True

	def decode_ENCODING_D(self, opbyte):
		#
		# <opcode> <REG> <REG> <REG>
		#
		self.cmd.Op1.type = o_reg
		self.cmd.Op1.dtyp = dt_byte
		self.cmd.Op1.reg = ua_next_byte()

		self.cmd.Op2.type = o_reg
		self.cmd.Op2.dtyp = dt_byte
		self.cmd.Op2.reg = ua_next_byte()

		self.cmd.Op3.type = o_reg
		self.cmd.Op3.dtyp = dt_byte
		self.cmd.Op3.reg = ua_next_byte()

		return True


	def decode_ENCODING_E(self, opbyte):
		#
		# <opcode> <REG> <IMM_16>
		#
		self.cmd.Op1.type = o_reg
		self.cmd.Op1.dtyp = dt_byte
		self.cmd.Op1.reg = ua_next_byte()

		self.cmd.Op2.type = o_imm
		self.cmd.Op2.dtyp = dt_word
		self.cmd.Op2.value = ua_next_word()

		return True


	def decode_ENCODING_F(self, opbyte):
		#
		# <opcode> <PADD8> <IMM_16>
		#
		padding = ua_next_byte()

		self.cmd.Op1.type = o_imm
		self.cmd.Op1.dtyp = dt_word
		self.cmd.Op1.value = ua_next_word()

 		return True



	def go_back(self, offset):
		return -(0xffff - offset + 1)


	def decode_JMP(self, opbyte):

		padding = ua_next_byte()

		self.cmd.Op1.type = o_near
		self.cmd.Op1.dtyp = dt_word
		offset = ua_next_word()

		if offset & 0x8000 :
			jump_to = self.cmd.ea + self.go_back(offset) + 4
		else :
			jump_to = self.cmd.ea + offset + 4

		self.cmd.Op1.addr = jump_to
 		return True


	def decode_CALL(self, opbyte):
		return self.decode_JMP(opbyte)



	decode_ADD      = decode_ENCODING_D
	decode_ADDLVAL  = decode_ENCODING_E
	decode_SUB      = decode_ENCODING_D
	decode_SUBLVAL  = decode_ENCODING_E
	decode_MUL      = decode_ENCODING_D
	decode_MULLVAL  = decode_ENCODING_E
	decode_DIV      = decode_ENCODING_D
	decode_DIVLVAL  = decode_ENCODING_E
	decode_MOD      = decode_ENCODING_D
	decode_MODLVAL  = decode_ENCODING_E
	decode_AND      = decode_ENCODING_D
	decode_ANDLVAL  = decode_ENCODING_E
	decode_OR       = decode_ENCODING_D
	decode_ORLVAL   = decode_ENCODING_E
	decode_XOR      = decode_ENCODING_D
	decode_XORLVAL  = decode_ENCODING_E

	decode_JMP = decode_JMP
	decode_JE = decode_JMP
	decode_JNE = decode_JMP
	decode_JL = decode_JMP
	decode_JLE = decode_JMP
	decode_JG = decode_JMP
	decode_JGE = decode_JMP

	decode_CALL = decode_CALL
	decode_CALLR = decode_ENCODING_B
	decode_RET = decode_ENCODING_B

	decode_LOAD = decode_ENCODING_E
	decode_LOADR = decode_ENCODING_C
	decode_LOADBR = decode_ENCODING_C
	def decode_LOADB(self, opbyte):
		#
		# <opcode> <REG> <IMM_16 & 0x00FF>
		#
		self.cmd.Op1.type = o_reg
		self.cmd.Op1.dtyp = dt_byte
		self.cmd.Op1.reg = ua_next_byte()

		self.cmd.Op2.type = o_imm
		self.cmd.Op2.dtyp = dt_word
		self.cmd.Op2.reg = ua_next_word() & 0x00FF

		return True

	decode_STOR = decode_ENCODING_E
	decode_STORR = decode_ENCODING_C
	decode_STORBR = decode_ENCODING_C
	def decode_STORB(self, opbyte):
		#
		# <opcode> <REG> <IMM_16 & 0x00FF>
		#
		self.cmd.Op1.type = o_reg
		self.cmd.Op1.dtyp = dt_byte
		self.cmd.Op1.reg = ua_next_byte()

		self.cmd.Op2.type = o_imm
		self.cmd.Op2.dtyp = dt_word
		self.cmd.Op2.reg = ua_next_word()  & 0x00FF

		return True

	decode_IN = decode_ENCODING_B
	decode_OUT = decode_ENCODING_B

	decode_PUSH = decode_ENCODING_B
	decode_PUSHLVAL = decode_ENCODING_F
	decode_POP = decode_ENCODING_B

	decode_MOV = decode_ENCODING_C
	decode_MOVLVAL = decode_ENCODING_E

	decode_CMP = decode_ENCODING_C
	decode_CMPLVAL = decode_ENCODING_E

	decode_HLT = decode_ENCODING_A
	decode_SYSCALL = decode_ENCODING_A
	decode_NOP = decode_ENCODING_A


	def ana(self):
		"""
		Decodes an instruction into the C global variable 'cmd'
		"""

		# take opcode byte
		opcode = ua_next_byte()

		# opcode supported?
		try:
			ins = self.itable[opcode]
		except:
			print "Invalid opcode %#x" % opcode
			return 0

		# set default itype
		self.cmd.itype = getattr(self, 'itype_' + ins.name)

		# call the decoder
		if ins.d(opcode):
			return self.cmd.size
		else:
			return 0


	def handle_operand(self, op, isRead):
		uFlag	 = self.get_uFlag()
		is_offs   = isOff(uFlag, op.n)
		dref_flag = dr_R if isRead else dr_W
		def_arg   = isDefArg(uFlag, op.n)
		optype	= op.type

		# create code xrefs
		if optype == o_imm:
			if is_offs:
				ua_add_off_drefs(op, dr_O)

		# create data xrefs
		elif optype == o_displ:
			if is_offs:
				ua_add_off_drefs(op, dref_flag)
		elif optype == o_mem:
			ua_add_dref(op.offb, op.addr, dref_flag)
		elif optype == o_near:
			itype = self.cmd.itype
			if itype == self.itype_CALL:
				fl = fl_CN
			else:
				fl = fl_JN
			ua_add_cref(op.offb, op.addr, fl)

	def emu(self):
		"""
		Emulate instruction, create cross-references, plan to analyze
		subsequent instructions, modify flags etc. Upon entrance to this function
		all information about the instruction is in 'cmd' structure.
		If zero is returned, the kernel will delete the instruction.
		"""
		aux = self.get_auxpref()
		Feature = self.cmd.get_canon_feature()

		if Feature & CF_USE1:
			self.handle_operand(self.cmd.Op1, 1)
		if Feature & CF_CHG1:
			self.handle_operand(self.cmd.Op1, 0)
		if Feature & CF_USE2:
			self.handle_operand(self.cmd.Op2, 1)
		if Feature & CF_CHG2:
			self.handle_operand(self.cmd.Op2, 0)
		if Feature & CF_USE3:
			self.handle_operand(self.cmd.Op3, 1)
		if Feature & CF_CHG3:
			self.handle_operand(self.cmd.Op3, 0)
		if Feature & CF_JUMP:
			QueueSet(Q_jumps, self.cmd.ea)

		if (Feature & CF_STOP == 0) :
			ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

		return 1

	# outop behavior
	# define the processor entry point function which instantiates
	# and returns an instance of processor_t
	def outop(self, op):
		"""
		Generate text representation of an instructon operand.
		This function shouldn't change the database, flags or anything else.
		All these actions should be performed only by u_emu() function.
		The output text is placed in the output buffer initialized with init_output_buffer()
		This function uses out_...() functions from ua.hpp to generate the operand text
		Returns: 1-ok, 0-operand is hidden.
		"""
		optype = op.type
		fl = op.specval
		signed = OOF_SIGNED if fl & self.FL_SIGNED != 0 else 0

		if optype == o_reg:
			out_register(self.regNames[op.reg])

		elif optype == o_imm:
			OutValue(op, OOFW_IMM | signed | (OOFW_32 if self.PTRSZ == 4 else OOFW_64))

		elif optype in [o_near, o_mem]:
			r = out_name_expr(op, op.addr, BADADDR)
			if not r:
				out_tagon(COLOR_ERROR)
				OutLong(op.addr, 16)
				out_tagoff(COLOR_ERROR)
				QueueSet(Q_noName, self.cmd.ea)

		elif optype == o_displ:
			indirect = fl & self.FL_INDIRECT != 0
			if indirect:
				out_symbol('[')

			out_register(self.regNames[op.reg])

			if op.addr != 0:
				OutValue(op, OOF_ADDR | OOFW_16 | signed | OOFS_NEEDSIGN)

			if indirect:
				out_symbol(']')
		else:
			return False

		return True

	# Generate text representation of an instruction in 'cmd'
	# structure. This function shouldn't change the database, flags or
	# anything else. All these actions should be performed only by
	# u_emu() function.
	def out(self):
		# Init output buffer
		buf = idaapi.init_output_buffer(1024)

		postfix = ""

		# First display size of first operand if it exists
		if self.cmd.auxpref & self.FL_OP1 != 0:
			postfix += self.fl_to_str(self.cmd.Op1.specval)

		# Display opertion size
		if self.cmd.auxpref & self.FL_32:
			postfix += "32"
		elif self.cmd.auxpref & self.FL_64:
			postfix += "64"

		# Display if native or not native (for CALL)
		if self.cmd.auxpref & self.FL_NATIVE:
			postfix += "EX"

		# Display size of instruction
		if self.cmd.auxpref & (self.FL_B | self.FL_W | self.FL_D | self.FL_Q) != 0:
			postfix += self.fl_to_str(self.cmd.auxpref)

		if self.cmd.auxpref & self.FL_CS:
			postfix += "CS"
		elif self.cmd.auxpref & self.FL_NCS:
			postfix += "CC"

		OutMnem(15, postfix)

		out_one_operand( 0 )

		for i in xrange(1, 3):
			op = self.cmd[i]

			if op.type == o_void:
				break

			out_symbol(',')
			OutChar(' ')
			out_one_operand(i)

		term_output_buffer()

		cvar.gl_comm = 1
		MakeLine(buf)


def PROCESSOR_ENTRY():
	return hsvm_processor_t()
