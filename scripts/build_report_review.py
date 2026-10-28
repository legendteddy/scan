"""Build synthetic report UX cases and an optional bounded Scan-on-Scan review.

Writes outside the repository when --output points at an owner review directory.
No fixture executes target code. The self review explicitly separates inventory
from the small set of source relationships reviewed by this script's author.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import json
from pathlib import Path
import tempfile

from scan_core import ScanConfig, SemanticStateBuilder, canonical_state_json, render_report, scan_project
from scan_core.reuse import SemanticCheckDefinition, SemanticRegistration

ROOT = Path(__file__).resolve().parents[1]


def semantic(state, *, findings=3, relationships=5, unknowns=2, long=False):
    builder = SemanticStateBuilder(state)
    a = next(a for a in state['artifacts'] if a['path_kind'] == 'file' and a['content_identity'])
    eid = builder.add_evidence(artifact_id=a['id'], locator=a['locator'], kind='static',
        claim='Synthetic presentation case', result='Fixture source contains a bounded static example.',
        method='Synthetic authoring for UI acceptance', limitations='Synthetic example; no runtime claim',
        source_digest=a['content_identity'], producer_kind='human', producer_name='scan-report-fixtures', producer_version='1',
        record_id='e:synthetic:' + ('long-identifier-' * 18 if long else 'source'))
    names = ['Inventory', 'Canonical state', 'Report renderer', 'Safety validator', 'Packaged shell', 'CLI', 'Reuse gate', 'Privacy boundary', 'Baseline', 'Checks']
    ids = [builder.add_component(name=n, purpose=f'{n} in a synthetic presentation case.', boundaries='Synthetic only',
                               artifact_ids=[a['id']], evidence_ids=[eid]) for n in names[:max(2, min(relationships + 1, 10))]]
    for i in range(relationships):
        builder.add_relationship(from_id=ids[i % len(ids)], to_id=ids[(i + 1) % len(ids)], kind='supplies',
            explanation=f'Recorded relationship {i + 1}; the source supplies data to the named target.',
            evidence_ids=[eid], confidence='high', verification_state='static')
    for i in range(findings):
        builder.add_finding(title=f'{["Inspection boundary needs review", "A source assumption needs verification", "Keep evidence provenance visible"][i % 3]} ({i + 1})',
            impact='An unsupported assumption could lead a reader to overestimate what was inspected.',
            severity=['high', 'medium', 'low'][i % 3], confidence=['high', 'medium', 'low'][i % 3], verification_state='static',
            artifact_ids=[a['id']], evidence_ids=[eid], uncertainty='Synthetic static example; runtime behavior was not observed.',
            recommendation='Review the declared boundary and verify the assumption against source.',
            safe_verification='Read the linked source; obtain authorization before executing target code.')
    for i in range(unknowns):
        builder.add_unknown(question=f'Is runtime assumption {i + 1} verified?', reason='No runtime observation was collected.',
            impact='Static evidence cannot establish deployed behavior.', next_safe_step='Obtain an authorized runtime observation.',
            artifact_ids=[a['id']], evidence_ids=[eid])
    builder.set_summary(condition='Static review found open questions that need verification.', readiness='not established')
    return builder.build()


def build_cases(output: Path, *, self_scan: bool = False):
    output.mkdir(parents=True, exist_ok=True)
    states = {}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'app.txt').write_text('Synthetic report acceptance input.\n', encoding='utf-8')
        def scan():
            return scan_project(ScanConfig(root=root, baseline_mode='none')).state
        small = scan()
        small['project']['name'] = 'Small project'
        states['small-clean'] = small
        states['many-findings'] = semantic(small, findings=24, relationships=14)
        states['unknown-heavy'] = semantic(small, findings=1, unknowns=12)
        states['zero-findings-with-unknowns'] = semantic(small, findings=0, unknowns=5)
        deep = root / ('long-path-segment-' * 8)
        deep.mkdir()
        (deep / ('evidence-identifier-' * 7 + '.txt')).write_text('Long locator fixture', encoding='utf-8')
        states['long-identifiers'] = semantic(scan(), long=True)
        # Separate inventory and semantic ledger stress cases, each generated from real bounded inputs.
        for i in range(200):
            (root / f'artifact-{i:03}.txt').write_text(f'Fixture {i}\n', encoding='utf-8')
        large = scan()
        states['large-inventory'] = large
        ledger = SemanticStateBuilder(small)
        a = small['artifacts'][0]
        for i in range(180):
            ledger.add_evidence(record_id=f'e:ledger:{i}', artifact_id=a['id'], locator=a['locator'], kind='static',
                claim=f'Synthetic observation {i}', result='Technical detail remains in the audit ledger.',
                method='Synthetic presentation case', limitations='Synthetic only', source_digest=a['content_identity'],
                producer_kind='human', producer_name='scan-report-fixtures', producer_version='1')
        states['large-evidence-ledger'] = ledger.build()
        # Exercise the real baseline and reuse gate, rather than fabricating freshness metadata.
        baseline_file = root.parent / (root.name + '-baseline.json')
        try:
            b = SemanticStateBuilder(small)
            definition = SemanticCheckDefinition(id='check:fixture', category='maintainability', title='Fixture source review',
                scope='app.txt', method='Bounded static source review')
            b.add_check(record_id=definition.id, category=definition.category, title=definition.title, scope=definition.scope,
                method=definition.method, status='not_assessed', artifact_ids=[], evidence_ids=[], related_ids=[],
                verification_state='unverified', result='Not assessed', limitations='Synthetic fixture', reason='Needs review', next_step='Read source')
            b.add_evidence(record_id='e:reusable', artifact_id=a['id'], locator=a['locator'], kind='static',
                claim='Reusable source observation', result='Static source bytes reviewed.', method=definition.method,
                limitations='Static only; runtime unverified', source_digest=a['content_identity'],
                producer_kind='local-model', producer_name='fixture-agent', producer_version='1',
                evidence_class='static_semantic', check_id=definition.id)
            baseline_file.write_text(canonical_state_json(b.build()), encoding='utf-8')
            cfg = ScanConfig(root=root, baseline_mode='explicit', baseline_path=baseline_file)
            reg = SemanticRegistration('local-model', 'fixture-agent', '1', (definition,))
            states['verified-reuse'] = scan_project(cfg, semantic_registrations=(reg,)).state
            (root / 'app.txt').write_text('Changed source\n', encoding='utf-8')
            states['repeat-baseline'] = scan_project(cfg, semantic_registrations=(reg,)).state
        finally:
            baseline_file.unlink(missing_ok=True)
    if self_scan:
        states['scan-on-scan'] = self_review()
    for name, state in states.items():
        if name != 'scan-on-scan':
            state['project']['name'] = name.replace('-', ' ').capitalize()
        (output / (name + '.json')).write_text(canonical_state_json(state), encoding='utf-8')
        render_report(state, output / (name + '.html'))
    return states


def self_review():
    state = scan_project(ScanConfig(root=ROOT, baseline_mode='none',
        excludes=('build/**', '**/__pycache__/**', '**/*.egg-info/**', 'dist/**', '.venv/**'))).state
    b = SemanticStateBuilder(state)
    artifacts = {a['locator']: a for a in state['artifacts']}
    reviewed = ('src/scan_core/render.py', 'src/scan_core/report/shell.html', 'src/scan_core/validate.py',
                'src/scan_core/core.py', 'src/scan_core/builder.py')
    evidence = {}
    components = {}
    for locator in reviewed:
        a = artifacts[locator]
        # This evidence names exactly the authored source review, not an automatic semantic analyzer.
        evidence[locator] = b.add_evidence(artifact_id=a['id'], locator=locator, kind='static',
            claim='Phase B source boundary reviewed', result={
                reviewed[0]: 'render_html validates canonical state, escapes target text and fills the packaged shell; render_report validates the output.',
                reviewed[1]: 'Static shell orders verdict, findings, changes, coverage, architecture, actions and audit; native details disclose receipts.',
                reviewed[2]: 'validate_report checks state, conservative HTML safety and visible-count agreement.',
                reviewed[3]: 'scan_project inventories the target and produces canonical state before report rendering.',
                reviewed[4]: 'SemanticStateBuilder validates referenced records and final state.',
            }[locator], method='Bounded source inspection during Phase B implementation',
            limitations='Static call and markup review only. No runtime or independent security certification claim.',
            source_digest=a['content_identity'], producer_kind='local-model', producer_name='Codex Phase B authored review', producer_version='1')
        components[locator] = b.add_component(name=Path(locator).name if 'shell' not in locator else 'Report shell',
            purpose={'render.py': 'Present validated evidence for human review.', 'shell.html': 'Supply static layout and native disclosures.',
                     'validate.py': 'Enforce canonical state and conservative HTML safety.', 'core.py': 'Inventory and orchestrate Scan.',
                     'builder.py': 'Author evidence-backed semantic records.'}[Path(locator).name],
            artifact_ids=[a['id']], evidence_ids=[evidence[locator]], boundaries='Only the named source file was inspected for this relationship map.')
    for source, target, kind, explanation in (
        (reviewed[3], reviewed[0], 'calls', 'Scan orchestration renders the completed state when an HTML output is requested.'),
        (reviewed[0], reviewed[1], 'reads', 'The renderer loads the shell through importlib.resources.'),
        (reviewed[0], reviewed[2], 'validates with', 'Canonical input and written HTML are validated at the rendering boundary.'),
        (reviewed[4], reviewed[2], 'validates with', 'The semantic builder validates completed authored state.'),
    ):
        b.add_relationship(from_id=components[source], to_id=components[target], kind=kind, explanation=explanation,
                           evidence_ids=[evidence[source], evidence[target]], confidence='high', verification_state='static')
    b.add_unknown(question='Do all supported browsers expand closed disclosures when printing?', reason='Print disclosure styling is tested in Chromium; other engines have not been captured.',
        impact='Readers using other print engines may need to open disclosures before printing.',
        next_safe_step='Review a print preview in the intended browser and expand receipts if necessary.', evidence_ids=[evidence[reviewed[1]]])
    b.add_unknown(question='Has the owner accepted the rendered reading experience?', reason='Phase B stops at owner review.',
        impact='Automated assertions do not establish visual acceptance.', next_safe_step='Review the five viewport captures and PDF before approving the PR.')
    b.set_summary(condition='Inventory is documented; the report reading flow is rebuilt. Owner visual review remains open.',
        overview='Scan reviews its report presentation boundary using static source evidence.', readiness='owner review required',
        limitations='Whole-project inventory is broader than the five-file semantic review. Runtime correctness and cross-browser print behavior are not established.',
        priorities=['Review the rendered report and proof before approval'])
    result = b.build()
    result['project']['name'] = 'Scan — self-review'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--self-scan', action='store_true')
    args = parser.parse_args()
    result = build_cases(args.output.resolve(), self_scan=args.self_scan)
    print(f'Wrote {len(result)} validated report cases to {args.output.resolve()}')
