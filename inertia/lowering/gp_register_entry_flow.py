"""Layer: Lowering.

Responsibility: Expose structured-C execution order for GP entry-version capture.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBreak,
    CConstant,
    CContinue,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CGoto,
    CIfBreak,
    CIfElse,
    CLabel,
    CReturn,
    CStatement,
    CStatements,
    CSwitchCase,
    CWhileLoop,
)


@dataclass
class _Step8616:
    """An atomic evaluation and its successor positions in the function body."""

    node: object
    successors: tuple[int, ...]


@dataclass(frozen=True)
class GPEntryFlow8616:
    """Structured-C execution positions, not a lexical statement ordering."""

    _entry: int
    _steps: tuple[_Step8616, ...]

    def reads_after_write(
        self, reads: Callable[[object], bool], writes: Callable[[object], bool], calls: Callable[[object], bool],
    ) -> bool:
        """Find a reachable read with an earlier lane write on the same path."""
        pending = [(self._entry, False)]
        visited: set[tuple[int, bool]] = set()
        while pending:
            position, overwritten = pending.pop()
            if (position, overwritten) in visited:
                continue
            visited.add((position, overwritten))
            step = self._steps[position]
            if step.node is not None:
                overwritten |= calls(step.node)
                write = writes(step.node)
                # An ordinary assignment reads its operands before its store.
                # An opaque subtree with a write has no such ordering proof.
                if (overwritten or (write and not isinstance(step.node, CAssignment))) and reads(step.node):
                    return True
                overwritten |= write
            pending.extend((successor, overwritten) for successor in step.successors)
        return False


@dataclass(frozen=True)
class _JumpTargets8616:
    """Lexically enclosing break and continue destinations."""

    break_to: int
    continue_to: int


@dataclass
class _GPEntryFlowBuilder8616:
    """Build each statement with an explicit continuation; resolve gotos last."""

    steps: list[_Step8616] = field(default_factory=lambda: [_Step8616(None, ())])
    labels: dict[int, int] = field(default_factory=dict)
    label_addresses: dict[tuple[int, int | None], int] = field(default_factory=dict)
    gotos: list[tuple[int, CGoto]] = field(default_factory=list)

    def _step(self, node: object, *successors: int) -> int:
        """Reserve a position that may be the destination of a backedge."""
        self.steps.append(_Step8616(node, successors))
        return len(self.steps) - 1

    def _branch(self, position: int, yes: int, no: int) -> None:
        """Link a condition to its alternatives, excluding a proven constant arm."""
        step = self.steps[position]
        if step.node is None:
            step.successors = (yes,)
        elif isinstance(step.node, CConstant) and isinstance(step.node.value, int):
            step.successors = (yes if step.node.value else no,)
        else:
            step.successors = (yes, no)

    def _loop(self, node: CWhileLoop | CDoWhileLoop | CForLoop, following: int) -> int:
        """Wire loop tests, body, and iterator in execution order."""
        condition = self._step(node.condition)
        iterator = condition
        if isinstance(node, CForLoop):
            iterator = self._build(node.iterator, condition, _JumpTargets8616(following, condition))
        body = self._build(node.body, iterator, _JumpTargets8616(following, iterator))
        self._branch(condition, body, following)
        if isinstance(node, CDoWhileLoop):
            return body
        if isinstance(node, CForLoop):
            return self._build(node.initializer, condition, _JumpTargets8616(following, iterator))
        return condition

    def _selection(self, node: CIfElse | CSwitchCase, following: int, jumps: _JumpTargets8616) -> int:
        """Keep alternatives separate until a real join or switch fallthrough."""
        if isinstance(node, CIfElse):
            otherwise = self._build(node.else_node, following, jumps)
            for condition, arm in reversed(node.condition_and_nodes):
                branch = self._step(condition)
                self._branch(branch, self._build(arm, following, jumps), otherwise)
                otherwise = branch
            return otherwise
        case_jumps = _JumpTargets8616(following, jumps.continue_to)
        fallthrough = self._build(node.default, following, case_jumps)
        destinations = [fallthrough]
        for _, arm in reversed(node.cases):
            fallthrough = self._build(arm, fallthrough, case_jumps)
            destinations.append(fallthrough)
        return self._step(node.switch, *destinations)

    def _transfer(self, node: CLabel | CGoto | CReturn | CBreak | CContinue, following: int, jumps: _JumpTargets8616) -> int:
        """Resolve local transfers without introducing a lexical fallthrough."""
        if isinstance(node, CLabel):
            position = self._step(None, following)
            self.labels[id(node)] = position
            address, index = node.tags.get("ins_addr"), node.tags.get("block_idx")
            if isinstance(address, int) and (index is None or isinstance(index, int)):
                self.label_addresses[address, index] = position
            return position
        if isinstance(node, CGoto):
            position = self._step(node.target if isinstance(node.target, CExpression) else None)
            self.gotos.append((position, node))
            return position
        if isinstance(node, CBreak):
            return jumps.break_to
        if isinstance(node, CContinue):
            return jumps.continue_to
        return self._step(node.retval)

    def _build(self, node: object, following: int, jumps: _JumpTargets8616) -> int:
        """Build one structured statement, treating all other nodes as atomic."""
        if node is None:
            return following
        if isinstance(node, CStatements):
            for stmt in reversed(node.statements):
                following = self._build(stmt, following, jumps)
            return following
        if isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop)):
            return self._loop(node, following)
        if isinstance(node, (CIfElse, CSwitchCase)):
            return self._selection(node, following, jumps)
        if isinstance(node, (CLabel, CGoto, CReturn, CBreak, CContinue)):
            return self._transfer(node, following, jumps)
        if isinstance(node, CIfBreak):
            position = self._step(node.condition)
            self._branch(position, jumps.break_to, following)
            return position
        return self._step(node, following)

    def _goto_destinations(self, jump: CGoto) -> tuple[int, ...]:
        """Bind direct jumps by coordinates; unresolved jumps may reach local labels."""
        if isinstance(jump.target, int):
            coordinate = (jump.target, jump.target_idx)
            position = self.label_addresses.get(coordinate)
            if position is None and jump.codegen is not None:
                label = jump.codegen.map_addr_to_label.get(coordinate)
                position = self.labels.get(id(label))
            if position is not None:
                return (position,)
        return tuple(self.labels.values())

    def build(self, root: CStatement) -> GPEntryFlow8616:
        """Return execution order for this body, including all internal backedges."""
        entry = self._build(root, 0, _JumpTargets8616(0, 0))
        for position, jump in self.gotos:
            self.steps[position].successors = self._goto_destinations(jump)
        return GPEntryFlow8616(entry, tuple(self.steps))


def build_gp_entry_flow_8616(root: CStatement) -> GPEntryFlow8616:
    """Build the per-body GP entry-version reachability model."""
    return _GPEntryFlowBuilder8616().build(root)
