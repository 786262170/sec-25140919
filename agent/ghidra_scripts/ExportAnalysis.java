//@category ReActAgent

import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;

public class ExportAnalysis extends GhidraScript {
    private String outDir;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        outDir = (args.length > 0) ? args[0] : "/tmp/ghidra_out";
        new File(outDir).mkdirs();
        Program prog = getCurrentProgram();
        if (prog == null) { println("[!] No program"); return; }
        println("[*] Exporting: " + prog.getName());
        exportFunctions(prog);
        exportDecompiled(prog);
        exportXrefs(prog);
        exportMemory(prog);
        exportCallgraph(prog);
        println("[*] Done -> " + outDir);
    }

    String esc(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') sb.append("\\\"");
            else if (c == '\\') sb.append("\\\\");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\r') sb.append("\\r");
            else if (c == '\t') sb.append("\\t");
            else sb.append(c);
        }
        sb.append("\"");
        return sb.toString();
    }

    void save(String fn, String data) throws Exception {
        try (PrintWriter w = new PrintWriter(new File(outDir, fn))) { w.print(data); }
    }

    void exportFunctions(Program prog) throws Exception {
        FunctionManager fm = prog.getFunctionManager();
        StringBuilder sb = new StringBuilder("[\n");
        boolean first = true;
        for (Function f : fm.getFunctions(true)) {
            if (!first) sb.append(",\n"); first = false;
            sb.append("  {\"name\":").append(esc(f.getName()));
            sb.append(",\"address\":").append(esc(f.getEntryPoint().toString()));
            sb.append(",\"size\":").append(f.getBody().getNumAddresses());
            sb.append(",\"signature\":").append(esc(f.getSignature().toString()));
            String cc = f.getCallingConventionName();
            sb.append(",\"cconv\":").append(esc(cc != null ? cc : ""));
            sb.append(",\"no_return\":").append(f.hasNoReturn());
            sb.append(",\"external\":").append(f.isExternal());
            String cmt = f.getComment();
            sb.append(",\"comment\":").append(esc(cmt != null ? cmt : ""));
            sb.append("}");
        }
        sb.append("\n]");
        save("ghidra_functions.json", sb.toString());
        println("[+] functions: " + fm.getFunctionCount());
    }

    void exportDecompiled(Program prog) throws Exception {
        FunctionManager fm = prog.getFunctionManager();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(prog);
        StringBuilder sb = new StringBuilder("{\n");
        boolean first = true;
        for (Function f : fm.getFunctions(true)) {
            if (f.isExternal()) continue;
            if (!first) sb.append(",\n"); first = false;
            String addr = f.getEntryPoint().toString();
            sb.append("  ").append(esc(addr)).append(":{\"addr\":").append(esc(addr));
            sb.append(",\"name\":").append(esc(f.getName()));
            DecompileResults r = dec.decompileFunction(f, 60, monitor);
            String code = (r != null && r.getDecompiledFunction() != null)
                ? r.getDecompiledFunction().getC() : "(failed)";
            sb.append(",\"code\":").append(esc(code));
            sb.append("}");
        }
        sb.append("\n}");
        save("ghidra_decompiled.json", sb.toString());
        println("[+] decompiled done");
        dec.dispose();
    }

    void exportXrefs(Program prog) throws Exception {
        FunctionManager fm = prog.getFunctionManager();
        ReferenceManager rm = prog.getReferenceManager();
        StringBuilder sb = new StringBuilder("{\n");
        boolean first = true;
        for (Function f : fm.getFunctions(true)) {
            if (f.isExternal()) continue;
            String addr = f.getEntryPoint().toString();
            ReferenceIterator it = rm.getReferencesTo(f.getEntryPoint());
            if (!it.hasNext()) continue;
            if (!first) sb.append(",\n"); first = false;
            sb.append("  ").append(esc(addr)).append(":[\n");
            boolean f2 = true;
            while (it.hasNext()) {
                Reference ref = it.next();
                if (!f2) sb.append(",\n"); f2 = false;
                sb.append("    {\"from\":").append(esc(ref.getFromAddress().toString()));
                sb.append(",\"type\":").append(esc(ref.getReferenceType().toString()));
                sb.append("}");
            }
            sb.append("\n  ]");
        }
        sb.append("\n}");
        save("ghidra_xrefs.json", sb.toString());
        println("[+] xrefs done");
    }

    void exportMemory(Program prog) throws Exception {
        Memory mem = prog.getMemory();
        StringBuilder sb = new StringBuilder("[\n");
        boolean first = true;
        for (MemoryBlock b : mem.getBlocks()) {
            if (!first) sb.append(",\n"); first = false;
            sb.append("  {\"name\":").append(esc(b.getName()));
            sb.append(",\"start\":").append(esc(b.getStart().toString()));
            sb.append(",\"end\":").append(esc(b.getEnd().toString()));
            sb.append(",\"size\":").append(b.getSize());
            String p = (b.isRead()?"r":"")+(b.isWrite()?"w":"")+(b.isExecute()?"x":"");
            sb.append(",\"perms\":").append(esc(p));
            sb.append(",\"init\":").append(b.isInitialized());
            sb.append("}");
        }
        sb.append("\n]");
        save("ghidra_memory.json", sb.toString());
        println("[+] memory: " + mem.getBlocks().length + " blocks");
    }

    void exportCallgraph(Program prog) throws Exception {
        FunctionManager fm = prog.getFunctionManager();
        Listing listing = prog.getListing();
        StringBuilder sb = new StringBuilder("{\n");
        boolean first = true;
        for (Function f : fm.getFunctions(true)) {
            if (f.isExternal()) continue;
            String caller = f.getEntryPoint().toString();
            java.util.List<String> c = new java.util.ArrayList<>();
            AddressSetView body = f.getBody();
            AddressIterator ai = body.getAddresses(true);
            while (ai.hasNext()) {
                Address a = ai.next();
                CodeUnit cu = listing.getCodeUnitAt(a);
                if (cu == null) continue;
                for (Reference ref : cu.getReferencesFrom()) {
                    String t = ref.getReferenceType().toString();
                    if (t.contains("CALL") || t.contains("JUMP")) {
                        Address to = ref.getToAddress();
                        Function tf = fm.getFunctionAt(to);
                        c.add("{\"to\":" + esc(to.toString()) +
                            ",\"name\":" + esc(tf != null ? tf.getName() : "unknown") +
                            ",\"type\":" + esc(t) + "}");
                    }
                }
            }
            if (c.isEmpty()) continue;
            if (!first) sb.append(",\n"); first = false;
            sb.append("  ").append(esc(caller)).append(":[\n");
            for (int i = 0; i < c.size(); i++) {
                if (i > 0) sb.append(",\n");
                sb.append("    ").append(c.get(i));
            }
            sb.append("\n  ]");
        }
        sb.append("\n}");
        save("ghidra_callgraph.json", sb.toString());
        println("[+] callgraph done");
    }
}
