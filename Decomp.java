import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import java.io.*;
import java.math.BigInteger;

public class Decomp extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    PrintWriter out = new PrintWriter(new FileWriter(a[0]));
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    Register tm = currentProgram.getLanguage().getRegister("TMode");
    for (int i = 1; i < a.length; i++) {
      long v = Long.parseLong(a[i], 16) & ~1L;
      Address ad = toAddr(v);
      currentProgram.getProgramContext().setValue(tm, ad, ad, BigInteger.ONE);
      disassemble(ad);
      Function f = getFunctionAt(ad);
      if (f == null) f = createFunction(ad, null);
      DecompileResults r = di.decompileFunction(f, 120, monitor);
      out.println("// ===== " + a[i]);
      out.println(r.getDecompiledFunction() != null
        ? r.getDecompiledFunction().getC() : "FAILED " + r.getErrorMessage());
    }
    out.close();
  }
}
