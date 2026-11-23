import runpy,sys,traceback
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp
original=CBinaryOp.__init__
seen=set()
def probe(self,op,*args,**kwargs):
 if op in ('Sub','Div'):
  stack=traceback.extract_stack(limit=14)[:-1]
  key=(op,tuple((s.filename,s.lineno) for s in stack[-4:]))
  if key not in seen:
   seen.add(key)
   print('ORIGIN',op, ''.join(traceback.format_list(stack)),file=sys.stderr,flush=True)
 original(self,op,*args,**kwargs)
CBinaryOp.__init__=probe
sys.argv[0]='decompile.py'
runpy.run_path('decompile.py',run_name='__main__')
