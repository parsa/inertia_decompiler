"""Track published FLAGS carriers and their branch-local writes across rewrites."""
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CIfElse, CStatements, CVariable
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616


def _carrier(variable):
    return variable.unified_variable if variable.unified_variable is not None else variable.variable


def packed_flag_publication_fingerprints_8616(root, fingerprint):
    """Compare the actual publisher and ordered writes, not just its tags."""
    publications = [
        node for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment) and (
            node.tags.get("inertia_status_flag_exit_phi_inputs")
            or node.tags.get("inertia_status_flag_exit_phi_candidates")
        )
    ]
    for publication in publications:
        carrier = _carrier(publication.rhs) if isinstance(publication.rhs, CVariable) else None
        writes = []

        def visit(node, path):
            if isinstance(node, CStatements):
                for statement in node.statements:
                    visit(statement, path)
            elif isinstance(node, CIfElse):
                prefix = path
                for _, body in node.condition_and_nodes:
                    visit(body, (*prefix, True))
                    prefix = (*prefix, False)
                if node.else_node is not None:
                    visit(node.else_node, prefix)
            elif (isinstance(node, CAssignment) and isinstance(node.lhs, CVariable)
                  and carrier is not None and _carrier(node.lhs) is carrier):
                writes.append((path, node.tags.get("ins_addr"), fingerprint(node.rhs)))

        visit(root, ())
        yield (
            publication.tags.get("ins_addr"),
            publication.tags.get("inertia_status_flag_exit_phi_inputs", ()),
            publication.tags.get("inertia_status_flag_exit_phi_candidates", ()),
            publication.tags.get("inertia_status_flag_exit_phi_carry_sources", ()),
            fingerprint(publication.lhs), fingerprint(publication.rhs), tuple(writes),
        )
