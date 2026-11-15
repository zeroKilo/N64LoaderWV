package n64loaderwv;

import java.util.ArrayList;
import java.util.List;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public final class N64ModemPrototypes {
	private static final CategoryPath CATEGORY = new CategoryPath("/N64/SDK");
	private static final DataType VOID = VoidDataType.dataType;
	private static final DataType S32 = IntegerDataType.dataType;
	private static final DataType U32 = UnsignedIntegerDataType.dataType;
	private static final DataType U64 = UnsignedLongLongDataType.dataType;
	private static final DataType PTR = pointer(VOID);
	private static final DataType MESG_PTR = pointer(PTR);
	private static final DataType QUEUE_PTR = opaquePointer("OSMesgQueue");
	private static final DataType THREAD_PTR = opaquePointer("OSThread");
	private static final DataType THREAD_PTR_PTR = pointer(THREAD_PTR);
	private static final DataType PI_PTR = opaquePointer("OSPiHandle");
	private static final DataType IO_PTR = opaquePointer("OSIoMesg");
	private static final DataType U32_PTR = pointer(U32);

	private record Argument(String name, DataType type) {
	}

	private record Signature(DataType result, List<Argument> arguments) {
	}

	private N64ModemPrototypes() {
	}

	private static DataType pointer(DataType type) {
		return new PointerDataType(type, 4);
	}

	private static DataType opaquePointer(String name) {
		return pointer(new StructureDataType(CATEGORY, name, 0));
	}

	private static Argument arg(String name, DataType type) {
		return new Argument(name, type);
	}

	private static Signature sig(DataType result, Argument... arguments) {
		return new Signature(result, List.of(arguments));
	}

	private static Signature lookup(String name) {
		return switch (name) {
		case "__osDisableInt" -> sig(S32);
		case "__osRestoreInt" -> sig(VOID, arg("mask", S32));
		case "osGetCount" -> sig(U32);
		case "osVirtualToPhysical" -> sig(U32, arg("vaddr", PTR));
		case "osSendMesg", "osJamMesg" -> sig(S32, arg("mq", QUEUE_PTR), arg("msg", PTR), arg("flag", S32));
		case "osRecvMesg" -> sig(S32, arg("mq", QUEUE_PTR), arg("msg", MESG_PTR), arg("flag", S32));
		case "osCreateMesgQueue" -> sig(VOID, arg("mq", QUEUE_PTR), arg("msg", MESG_PTR), arg("count", S32));
		case "bcopy" -> sig(VOID, arg("src", PTR), arg("dst", PTR), arg("size", U32));
		case "bzero" -> sig(VOID, arg("dst", PTR), arg("size", U32));
		case "bcmp" -> sig(S32, arg("src1", PTR), arg("src2", PTR), arg("size", U32));
		case "memcpy" -> sig(PTR, arg("dst", PTR), arg("src", PTR), arg("size", U32));
		case "memset" -> sig(PTR, arg("dst", PTR), arg("value", S32), arg("size", U32));
		case "osWritebackDCache", "osInvalDCache" -> sig(VOID, arg("vaddr", PTR), arg("nbytes", S32));
		case "osWritebackDCacheAll" -> sig(VOID);
		case "osEPiStartDma" -> sig(S32, arg("handle", PI_PTR), arg("message", IO_PTR), arg("direction", S32));
		case "osEPiReadIo", "__osEPiRawReadIo" ->
			sig(S32, arg("handle", PI_PTR), arg("devAddr", U32), arg("data", U32_PTR));
		case "osEPiWriteIo", "__osEPiRawWriteIo" ->
			sig(S32, arg("handle", PI_PTR), arg("devAddr", U32), arg("data", U32));
		case "__osEPiRawStartDma" -> sig(S32, arg("handle", PI_PTR), arg("direction", S32), arg("devAddr", U32),
				arg("dramAddr", PTR), arg("size", U32));
		case "__osPopThread" -> sig(THREAD_PTR, arg("queue", THREAD_PTR_PTR));
		case "__osEnqueueThread" -> sig(VOID, arg("queue", THREAD_PTR_PTR), arg("thread", THREAD_PTR));
		case "osStartThread", "osDestroyThread" -> sig(VOID, arg("thread", THREAD_PTR));
		case "osYieldThread" -> sig(VOID);
		case "osCreateRegion" ->
			sig(PTR, arg("startAddress", PTR), arg("length", U32), arg("bufferSize", U32), arg("alignSize", U32));
		case "osMalloc" -> sig(PTR, arg("region", PTR));
		case "osFree" -> sig(VOID, arg("region", PTR), arg("addr", PTR));
		default -> null;
		};
	}

	private static void applyGetTime(Program program, Function function)
			throws InvalidInputException, DuplicateNameException {
		var high = program.getRegister("v0_lo");
		var low = program.getRegister("v1_lo");
		if (!program.getLanguage().isBigEndian() || high == null || low == null || high.getBitLength() != 32
				|| low.getBitLength() != 32)
			throw new InvalidInputException("Required MIPS return registers unavailable");
		VariableStorage storage = new VariableStorage(program, high, low);
		ReturnParameterImpl result = new ReturnParameterImpl(U64, storage, program);
		function.updateFunction(null, result, FunctionUpdateType.CUSTOM_STORAGE, false, SourceType.IMPORTED,
				new Variable[0]);
		function.setVarArgs(false);
	}

	public static boolean apply(Program program, Function function, String name, MessageLog log) {
		try {
			if (name.equals("osGetTime")) {
				applyGetTime(program, function);
				return true;
			}
			Signature signature = lookup(name);
			if (signature == null)
				return false;
			List<Variable> parameters = new ArrayList<>();
			for (Argument argument : signature.arguments())
				parameters.add(new ParameterImpl(argument.name(), argument.type(), program));
			ReturnParameterImpl result = new ReturnParameterImpl(signature.result(), program);
			function.updateFunction(null, result, parameters, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false,
					SourceType.IMPORTED);
			function.setVarArgs(false);
			return true;
		} catch (InvalidInputException | DuplicateNameException ex) {
			log.appendMsg("  Could not apply SDK prototype " + name + ": " + ex.getMessage());
			return false;
		}
	}
}