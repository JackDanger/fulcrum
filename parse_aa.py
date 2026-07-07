import json, sys
art = json.load(open('/tmp/mmB2_amd_scoreboard.json'))
print("n=", art.get("n"), "src_sha=", art.get("src_sha"))
for bx in art["boxes"]:
    print("BOX", bx["id"], bx["cpu"])
    for c in bx["cells"]:
        st = c["state"]
        if st == "VERDICT":
            cell = c["cell"];
            print(f"  VERDICT T{cell['threads']:>2} {cell['comparator']:<24} "
                  f"{c['verdict']:<5} {c['criterion']:<20} "
                  f"ratio={c['ratio']:.4f} subj={c['subject_wall_median_ms']:.2f}ms "
                  f"cmp={c['comparator_wall_median_ms']:.2f}ms "
                  f"subjspread={c['subject_rel_spread']*100:.2f}% "
                  f"cmpspread={c['comparator_rel_spread']*100:.2f}% "
                  f"aa={ (c.get('aa_rel_spread') or 0)*100:.2f}% "
                  f"p={c['paired']['p_value']:.4f}")
        elif st == "VOID":
            cell = c.get("cell", {})
            keys = [k for k in c.keys() if k not in ("state","cell")]
            # dump relevant numeric fields
            def g(k, d=None): return c.get(k, d)
            print(f"  VOID    T{cell.get('threads'):>2} {cell.get('comparator',''):<24} "
                  f"reason={c.get('reason','?')}")
            # print all scalar fields for the void
            for k,v in c.items():
                if k in ("state","cell"): continue
                if isinstance(v,(int,float,str,bool)):
                    print(f"           {k} = {v}")
                elif isinstance(v,dict):
                    print(f"           {k}: "+", ".join(f"{kk}={vv}" for kk,vv in v.items() if isinstance(vv,(int,float,str,bool))))
        elif st == "REFUSED":
            cell = c.get("cell", {})
            print(f"  REFUSED T{cell.get('threads')} {cell.get('comparator','')} missing={c.get('missing')}")
