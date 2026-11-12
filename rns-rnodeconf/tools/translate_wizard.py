"""Translate the device and model menus of upstream rnodeconf's autoinstall
wizard (the statements between two line numbers) into the Rust body of
`choose_board` in src/wizard.rs.

Usage: translate_wizard.py <upstream rnodeconf.py> <first line> <last line>

It handles what those menus use: prints, Enter prompts, screen clears,
numeric choices read in try/except blocks, and if/elif chains assigning the
selected product, model, MCU, platform and firmware file."""
import ast, sys

src_path, first, last = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
tree = ast.parse(open(src_path).read())

def find_autoinstall(node):
    for n in ast.walk(node):
        if isinstance(n, ast.If) and isinstance(n.test, ast.Attribute) and n.test.attr == "autoinstall" \
                and isinstance(n.test.value, ast.Name) and n.test.value.id == "args" \
                and n.lineno < first and n.end_lineno > last:
            return n
    raise SystemExit("no autoinstall block")

block = find_autoinstall(tree)
stmts = [s for s in block.body if first <= s.lineno <= last]

INT_VARS = set()
OPT_U8 = {"selected_product", "selected_model", "selected_mcu", "selected_platform"}

def rs_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("{", "{{").replace("}", "}}") + '"'

def expr(e):
    if isinstance(e, ast.Constant):
        if e.value is None:
            return "None"
        if isinstance(e.value, bool):
            return "true" if e.value else "false"
        if isinstance(e.value, int):
            return str(e.value)
        if isinstance(e.value, str):
            return rs_str(e.value)
    if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name) and e.value.id == "ROM":
        return f"rom::{e.attr}"
    if isinstance(e, ast.Name):
        return e.id
    raise SystemExit(f"unsupported expr {ast.dump(e)} at {e.lineno}")

def cond(e, top=True):
    if isinstance(e, ast.BoolOp):
        op = " || " if isinstance(e.op, ast.Or) else " && "
        joined = op.join(cond(v, False) for v in e.values)
        return joined if top else "(" + joined + ")"
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return "!" + cond(e.operand, False)
    if isinstance(e, ast.Name):
        return e.id
    if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name) and e.value.id == "rnode":
        return e.attr
    if isinstance(e, ast.Compare) and len(e.ops) == 1:
        left, right = e.left, e.comparators[0]
        ops = {ast.Lt: "<", ast.Gt: ">", ast.Eq: "==", ast.NotEq: "!=", ast.LtE: "<=", ast.GtE: ">="}
        op = ops[type(e.ops[0])]
        l = expr(left)
        r = expr(right)
        if isinstance(left, ast.Name) and left.id in OPT_U8 and r != "None":
            r = f"Some({r})"
        if isinstance(left, ast.Name) and left.id == "fw_filename" and r == "None":
            return f"fw_filename.is_none()" if op == "==" else "fw_filename.is_some()"
        return f"{l} {op} {r}"
    raise SystemExit(f"unsupported cond {ast.dump(e)} at {e.lineno}")

def print_call(call, ind):
    end = "\n"
    for kw in call.keywords:
        if kw.arg == "end":
            end = kw.value.value
    if not call.args:
        text = ""
    else:
        a = call.args[0]
        if not (isinstance(a, ast.Constant) and isinstance(a.value, str)):
            raise SystemExit(f"print of non-constant at {call.lineno}")
        text = a.value
    if end == "\n":
        return [f"{ind}println!({rs_str(text)});"]
    return [f"{ind}print!({rs_str(text + end)});", f"{ind}flush();"]

def stmt(s, ind, in_try):
    out = []
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
        c = s.value
        name = c.func.id if isinstance(c.func, ast.Name) else None
        if name == "print":
            return print_call(c, ind)
        if name == "input":
            return [f"{ind}wait_for_enter();"]
        if name == "clear":
            return [f"{ind}clear_screen();"]
        if name == "graceful_exit":
            code = expr(c.args[0]) if c.args else "0"
            return [f"{ind}graceful_exit({code});"]
        if name == "exit":
            return [f"{ind}exit(0);"]
        if name == "print_donation_block":
            return [f"{ind}print_donation_block();"]
        raise SystemExit(f"unsupported call {name} at {s.lineno}")
    if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
        target = s.targets[0].id
        v = s.value
        # c_x = int(input())
        if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "int":
            INT_VARS.add(target)
            return [f"{ind}let {target} = py_int(&read_line()).ok_or(())?;"]
        # c_ok = input().lower()
        if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "lower":
            return [f"{ind}let {target} = read_line().trim_end_matches(['\\r', '\\n']).to_lowercase();"]
        # fw_filename = models[selected_model][4]
        if isinstance(v, ast.Subscript):
            return [f"{ind}{target} = selected_model.and_then(rom::model).and_then(|m| m.firmware).map(str::to_string);"]
        val = expr(v)
        if target in OPT_U8:
            val = "None" if val == "None" else f"Some({val})"
        elif target == "fw_filename":
            val = "None" if val == "None" else f"Some({val}.to_string())"
        return [f"{ind}{target} = {val};"]
    if isinstance(s, ast.If):
        out.append(f"{ind}if {cond(s.test)} {{")
        for b in s.body:
            out += stmt(b, ind + "    ", in_try)
        orelse = s.orelse
        while orelse:
            if len(orelse) == 1 and isinstance(orelse[0], ast.If):
                o = orelse[0]
                out.append(f"{ind}}} else if {cond(o.test)} {{")
                for b in o.body:
                    out += stmt(b, ind + "    ", in_try)
                orelse = o.orelse
            else:
                out.append(f"{ind}}} else {{")
                for b in orelse:
                    out += stmt(b, ind + "    ", in_try)
                orelse = []
        out.append(f"{ind}}}")
        return out
    if isinstance(s, ast.Raise):
        return [f"{ind}return Err(());"]
    if isinstance(s, ast.Try):
        out.append(f"{ind}let attempt = (|| -> Result<(), ()> {{")
        for b in s.body:
            out += stmt(b, ind + "    ", True)
        out.append(f"{ind}    Ok(())")
        out.append(f"{ind}}})();")
        out.append(f"{ind}if attempt.is_err() {{")
        for b in s.handlers[0].body:
            out += stmt(b, ind + "    ", False)
        out.append(f"{ind}}}")
        return out
    if isinstance(s, ast.Pass):
        return []
    raise SystemExit(f"unsupported stmt {type(s).__name__} at {s.lineno}")

lines = []
for s in stmts:
    lines += stmt(s, "    ", False)
print("\n".join(lines))
