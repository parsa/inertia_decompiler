import runpy,sys
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeGenerator
original=CStructuredCodeGenerator._handle_Expr_Convert
def probe(self,expr,**kwargs):
 result=original(self,expr,**kwargs)
 if True:
  print('WIDTH probe',repr(expr),type(expr.operand).__name__,type(result.expr).__name__,file=sys.stderr,flush=True)
 return result
CStructuredCodeGenerator._handle_Expr_Convert=probe
binary_original=CStructuredCodeGenerator._handle_Expr_BinaryOp
def binary_probe(self,expr,**kw):
 if True: print("SUB WIDTH",expr.bits,repr(expr),file=sys.stderr,flush=True)
 return binary_original(self,expr,**kw)
CStructuredCodeGenerator._handle_Expr_BinaryOp=binary_probe
sys.argv[0]='decompile.py'
runpy.run_path('decompile.py',run_name='__main__')
