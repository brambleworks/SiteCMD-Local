use std::{collections::BTreeMap, io, sync::mpsc, thread, time::Duration};

use serde::Deserialize;
use sitecmd_engine_host::{
    load,
    wants::{answer, HostIo, ReadBudget},
    Engine, EngineError, Interrupt,
};
use sitecmd_protocol::engine_abi::{
    AuditFileKind, AuditFileOffer, AuditFileRefusal, BodyRef, Brief, BriefTarget,
    BriefTargetLocation, CodeRuleInfo, DatabaseTargetOffer, DisplayPath, Done, EntryKind,
    FileAnalysisSource, FileLocation, FixTarget, FixTextTarget, FixUnavailable, Listing,
    ListingEntry, LocalSiteRequest, Refusal, RelPath, SchemaSnapshot, SessionBegin, Step, Task,
    Want, WantAnswer,
};
use sitecmd_protocol::vocab::{CheckResult, CheckStatus, Severity};

#[derive(Deserialize)]
struct Corpus {
    audit: Vec<AuditCase>,
    quote: QuoteCase,
    rule: CodeRuleInfo,
    local_page: LocalPageCase,
    want_parent: String,
    memory: String,
    interrupt: String,
    trap: String,
}

#[derive(Deserialize)]
struct AuditCase {
    name: String,
    files: BTreeMap<String, Option<Vec<u8>>>,
    total: u64,
    per_file: u64,
    #[serde(default)]
    preanswered: Vec<String>,
    issues: BTreeMap<String, String>,
    refusals: BTreeMap<String, Refusal>,
}

#[derive(Deserialize)]
struct QuoteCase {
    path: String,
    line: String,
    refusal: String,
}

#[derive(Deserialize)]
struct LocalPageCase {
    path: String,
    check_id: String,
    title: String,
    category: serde_json::Value,
}

impl HostIo for AuditCase {
    fn read(&self, path: &RelPath, _limit: u64) -> io::Result<Vec<u8>> {
        self.files[path.as_str()]
            .clone()
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn git_tracked(&self, _paths: &[RelPath]) -> io::Result<Vec<RelPath>> {
        panic!("unexpected Git request")
    }

    fn database_schema(&self, _offer: &DatabaseTargetOffer) -> Option<SchemaSnapshot> {
        panic!("unexpected database request")
    }
}

fn path(name: &str) -> RelPath {
    RelPath::parse(name).unwrap()
}

fn begin(operation: Task, files: impl IntoIterator<Item = ListingEntry>) -> SessionBegin {
    SessionBegin {
        task: operation,
        listing: Listing {
            entries: files.into_iter().collect(),
            ..Listing::default()
        },
        options: Default::default(),
        now_ms: 0,
        text_budget: 1024,
        host: Default::default(),
    }
}

fn entry(name: &str, size: u64) -> ListingEntry {
    ListingEntry {
        path: path(name),
        size,
        kind: EntryKind::File,
        ignored: false,
    }
}

fn audit_file(name: &str) -> SessionBegin {
    begin(Task::Audit {}, [entry(name, 0)])
}

fn replay_audit(engine: &Engine, case: &AuditCase) {
    let request = begin(
        Task::Audit {},
        case.files
            .iter()
            .map(|(name, body)| entry(name, body.as_ref().map_or(1, Vec::len) as u64)),
    );
    let mut budget = ReadBudget::new(case.total, case.per_file);
    for name in &case.preanswered {
        assert!(matches!(
            answer(
                &request,
                &mut budget,
                case,
                &Want::File { path: path(name) }
            )
            .into_parts()
            .0,
            WantAnswer::File { .. }
        ));
    }
    let mut session = engine.session(&Interrupt::new()).unwrap();
    let Step::Wants { wants } = session.begin(&request).unwrap() else {
        panic!("{}: missing file wants", case.name);
    };
    assert_eq!(
        wants,
        case.files
            .keys()
            .map(|name| Want::File { path: path(name) })
            .collect::<Vec<_>>(),
        "{}",
        case.name
    );
    let mut bodies = Vec::new();
    let answers = wants
        .iter()
        .map(|want| {
            let (mut answer, bytes) = answer(&request, &mut budget, case, want).into_parts();
            if let WantAnswer::File { body } = &mut answer {
                body.at = bodies.len().try_into().unwrap();
                bodies.extend(bytes);
            }
            answer
        })
        .collect();
    let Step::Done {
        done: Done::Audit(report),
    } = session.resume(answers, &bodies).unwrap()
    else {
        panic!("{}: missing audit report", case.name);
    };
    assert_eq!(report.issue_count, case.issues.len(), "{}", case.name);
    assert_eq!(report.issues.len(), case.issues.len(), "{}", case.name);
    let mut issues = BTreeMap::new();
    for issue in report.issues {
        let FileLocation::Listed(path) = issue.path else {
            panic!("{}: unexpected file location", case.name);
        };
        assert_eq!(issue.rule_id, "standin.rule");
        let evidence = issue.evidence.expect("stand-in records the byte length");
        assert!(issues.insert(path.as_str().to_owned(), evidence).is_none());
    }
    assert_eq!(issues, case.issues, "{}", case.name);
    assert_eq!(
        report.coverage,
        case.refusals
            .iter()
            .map(|(name, reason)| AuditFileRefusal {
                path: FileLocation::Listed(path(name)),
                reason: *reason,
            })
            .collect::<Vec<_>>(),
        "{}",
        case.name
    );
}

fn replay_other_shapes(engine: &Engine, quote: &QuoteCase) {
    let mut session = engine.session(&Interrupt::new()).unwrap();
    for (operation, expected) in [
        (
            Task::FixCatalog {},
            Done::FixCatalog(vec![sitecmd_protocol::engine_abi::FixerInfo {
                check_id: "standin.rule".into(),
                title: "Sample finding".into(),
                write_set: vec![path("vercel.json")],
            }]),
        ),
        (
            Task::FixText {
                targets: vec![FixTextTarget::Hosted {
                    category: "sample".into(),
                    title: "Sample finding".into(),
                    severity: sitecmd_protocol::vocab::Severity::Low,
                    url: "https://example.test".into(),
                }],
            },
            Done::FixText(vec![String::new()]),
        ),
        (
            Task::FixPlan {
                target: sitecmd_protocol::engine_abi::FixTarget {
                    check_id: "fixture.unknown".into(),
                    identity: "sample".into(),
                },
            },
            Done::FixUnavailable(sitecmd_protocol::engine_abi::FixUnavailable::NoTemplate),
        ),
    ] {
        assert_eq!(
            session.begin(&begin(operation, [])).unwrap(),
            Step::Done { done: expected }
        );
    }
    let target: BriefTarget = serde_json::from_value(serde_json::json!({
        "agent": "fixture", "attempt": 1, "check_id": "standin.rule", "description": "",
        "detected_stack": null, "likely_fix": null, "locations": [], "severity": "low",
        "site_url": "https://example.test", "title": "", "why_now": null
    }))
    .unwrap();
    assert_eq!(
        session
            .begin(&begin(
                Task::Brief {
                    target: target.clone()
                },
                []
            ))
            .unwrap(),
        Step::Done {
            done: Done::Brief(sitecmd_protocol::engine_abi::Brief {
                title: String::new(),
                body: String::new()
            })
        }
    );
    let body = BodyRef {
        at: 0,
        len: quote.line.len().try_into().unwrap(),
    };
    assert_eq!(
        session
            .begin(&begin(
                Task::Brief { target },
                [entry(&quote.path, u64::from(body.len))]
            ))
            .unwrap(),
        Step::Wants {
            wants: vec![Want::File {
                path: path(&quote.path)
            }]
        }
    );
    let Step::Done {
        done: Done::Brief(brief),
    } = session
        .resume(vec![WantAnswer::File { body }], quote.line.as_bytes())
        .unwrap()
    else {
        panic!("missing quoted brief");
    };
    assert_eq!(brief.body, quote.line);
    assert_eq!(quote.refusal, "handed_line");

    let files = session
        .analyze_files(
            &[FileAnalysisSource {
                location: FileLocation::Listed(path("analysis.txt")),
                path: "analysis.txt".into(),
            }],
            &Default::default(),
            |_| Some(b"xyz".to_vec()),
        )
        .unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "analysis.txt");
    assert_eq!(files[0].issues.len(), 1);
    assert_eq!(
        sitecmd_protocol::identity::code_producer_rule_id(&files[0].issues[0].id),
        "standin.rule"
    );
    assert_eq!(files[0].issues[0].evidence.as_deref(), Some("3"));
}

fn replay_local_page(engine: &Engine, page: &LocalPageCase) {
    let request = local_request(&page.path);
    let local = engine.local_site_evaluate(&request, &[]).unwrap();
    let [result] = local.results.as_slice() else {
        panic!("expected one local result, got {:?}", local.results);
    };
    assert_eq!(result.check_id, page.check_id);
    assert_eq!(result.title, page.title);
    assert_eq!(result.status, CheckStatus::Fail);
    assert_eq!(result.fix_prompt, None);
    assert_eq!(result.manual_fix, None);
    assert_eq!(local.score.low_count, 1);
    assert_eq!(local.score.overall, 100.0);
    assert_eq!(local.fix_points, [0]);
    assert_eq!(local.score.computed_at, request.now_ms);
    assert_eq!(
        serde_json::to_value(local.categories.unwrap()).unwrap(),
        serde_json::json!([page.category])
    );
}

fn local_request(page: &str) -> LocalSiteRequest {
    let url = format!("http://localhost/{page}");
    LocalSiteRequest {
        requested_url: url.clone(),
        final_url: url,
        status: 200,
        header_lines: vec![],
        body: BodyRef { at: 0, len: 0 },
        now_ms: 42,
        polish_only: false,
        categories: None,
    }
}

fn replay_limits(engine: &Engine, corpus: &Corpus) {
    let run = |name: &str| {
        engine
            .session(&Interrupt::new())
            .unwrap()
            .begin(&audit_file(name))
    };
    assert!(matches!(
        run(&corpus.want_parent),
        Err(EngineError::Malformed(_))
    ));
    for name in [&corpus.memory, &corpus.trap] {
        assert_eq!(
            run(name),
            Err(EngineError::Trap {
                module_version: engine.info().module_version.clone()
            }),
            "{name}"
        );
    }
    let interrupt = Interrupt::new();
    let mut session = engine.session(&interrupt).unwrap();
    let (ready, started) = mpsc::sync_channel(0);
    thread::scope(|scope| {
        scope.spawn(move || {
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            thread::sleep(Duration::from_millis(50));
            interrupt.trigger();
        });
        ready.send(()).unwrap();
        assert_eq!(
            session.begin(&audit_file(&corpus.interrupt)),
            Err(EngineError::Interrupted)
        );
    });
}

#[test]
fn standin_corpus_replays() {
    // Bug: The host can accept an unsafe guest response or misroute a valid transcript.
    let engine = load().unwrap();
    if engine.info().manifest_digest.as_str() != "0000000000000000" {
        return;
    }
    assert_eq!(engine.info().module_version, "standin");
    let corpus: Corpus = serde_json::from_str(include_str!("../standin/corpus.json")).unwrap();
    assert_eq!(
        engine.info().code_rules.as_slice(),
        std::slice::from_ref(&corpus.rule)
    );
    for case in &corpus.audit {
        replay_audit(&engine, case);
    }
    replay_other_shapes(&engine, &corpus.quote);
    replay_local_page(&engine, &corpus.local_page);
    replay_limits(&engine, &corpus);
}

#[test]
fn standin_audit_preserves_fixture_lines_and_offer_locations() {
    // A stand-in that skips fixtures or sanitizes its echo can hide host audit regressions.
    let engine = load().unwrap();
    if engine.info().module_version != "standin" {
        return;
    }
    let mut request = begin(
        Task::Audit {},
        [
            entry(".sitecmd/config.json", 2),
            entry("app/fixture-findings.txt", 5),
            entry("fixture-evidence.txt", 6),
        ],
    );
    request.options.inspect_local_databases = true;
    request.host.files = vec![
        AuditFileOffer {
            id: 0,
            path: DisplayPath::parse("collision/fixture-findings.txt").unwrap(),
            kind: AuditFileKind::Inventory {
                walk_index: 3,
                ignored: false,
            },
            size: 3,
        },
        AuditFileOffer {
            id: 1,
            path: DisplayPath::parse("prisma/dev.db").unwrap(),
            kind: AuditFileKind::DatabaseLocation {},
            size: 100,
        },
    ];
    let mut session = engine.session(&Interrupt::new()).unwrap();
    assert_eq!(
        session.begin(&request).unwrap(),
        Step::Wants {
            wants: vec![
                Want::File {
                    path: path("app/fixture-findings.txt"),
                },
                Want::File {
                    path: path("fixture-evidence.txt"),
                },
                Want::OfferedFile { id: 0 },
            ],
        }
    );
    let Step::Done {
        done: Done::Audit(report),
    } = session
        .resume(
            vec![
                WantAnswer::File {
                    body: BodyRef { at: 0, len: 5 },
                },
                WantAnswer::File {
                    body: BodyRef { at: 5, len: 6 },
                },
                WantAnswer::File {
                    body: BodyRef { at: 11, len: 3 },
                },
            ],
            b"a\n\nb\nx\n\nyy\n\nz\n",
        )
        .unwrap()
    else {
        panic!("missing audit report");
    };
    let listed = |name| FileLocation::Listed(path(name));
    assert_eq!(report.issue_count, 6);
    assert_eq!(report.low_count, 6);
    assert!(report.coverage.is_empty());
    assert_eq!(
        report
            .issues
            .iter()
            .map(|issue| (
                issue.id.as_str(),
                &issue.path,
                issue.id_path_offset,
                issue.line,
                issue.evidence.as_deref(),
            ))
            .collect::<Vec<_>>(),
        [
            (
                "standin.rule:app/fixture-findings.txt:1",
                &listed("app/fixture-findings.txt"),
                None,
                Some(1),
                Some("5")
            ),
            (
                "standin.rule:app/fixture-findings.txt:3",
                &listed("app/fixture-findings.txt"),
                None,
                Some(3),
                Some("5")
            ),
            (
                "standin.rule:fixture-evidence.txt:1",
                &listed("fixture-evidence.txt"),
                None,
                Some(1),
                Some("x")
            ),
            (
                "standin.rule:fixture-evidence.txt:3",
                &listed("fixture-evidence.txt"),
                None,
                Some(3),
                Some("yy")
            ),
            (
                "standin.rule::2",
                &FileLocation::Offer { id: 0 },
                Some(13),
                Some(2),
                Some("3")
            ),
            (
                "standin.rule::database",
                &FileLocation::Offer { id: 1 },
                Some(13),
                None,
                None
            ),
        ],
    );
    for (issue, source) in report.issues[2..4].iter().zip(["x", "yy"]) {
        assert_eq!(
            [
                Some(issue.title.as_str()),
                Some(issue.description.as_str()),
                issue.why_now.as_deref(),
                issue.likely_fix.as_deref(),
                issue.verify_hint.as_deref(),
                issue.confidence_reason.as_deref(),
            ],
            [Some(source); 6],
        );
    }
}

#[test]
fn standin_fix_plan_distinguishes_missing_and_satisfied_hosts() {
    // Returning a patch for an absent or already-correct file bypasses host refusal handling.
    let engine = load().unwrap();
    if engine.info().module_version != "standin" {
        return;
    }
    let mut session = engine.session(&Interrupt::new()).unwrap();
    let task = Task::FixPlan {
        target: FixTarget {
            check_id: "standin.rule".into(),
            identity: "sample".into(),
        },
    };
    assert_eq!(
        session.begin(&begin(task.clone(), [])).unwrap(),
        Step::Done {
            done: Done::FixUnavailable(FixUnavailable::NoHost)
        },
    );
    let file = "vercel.json";
    let bytes = b"{\"example\":true}\n";
    assert_eq!(
        session
            .begin(&begin(task, [entry(file, bytes.len() as u64)]))
            .unwrap(),
        Step::Wants {
            wants: vec![Want::File { path: path(file) }]
        },
    );
    let answer = WantAnswer::File {
        body: BodyRef {
            at: 0,
            len: bytes.len().try_into().unwrap(),
        },
    };
    assert_eq!(
        session.resume(vec![answer], bytes).unwrap(),
        Step::Done {
            done: Done::FixUnavailable(FixUnavailable::AlreadySatisfied { path: path(file) }),
        },
    );
}

#[test]
fn standin_renders_fix_text_and_briefs_for_its_rule() {
    // Empty or rewritten guidance leaves host prompt and brief tests without module text to verify.
    let engine = load().unwrap();
    if engine.info().module_version != "standin" {
        return;
    }
    let mut session = engine.session(&Interrupt::new()).unwrap();
    let web: CheckResult = serde_json::from_value(serde_json::json!({
        "checkId": "standin.rule", "category": "reliability", "title": "Web fixture",
        "description": "", "status": "fail", "severity": "low"
    }))
    .unwrap();
    let location = "app/fixture-findings.txt";
    let code = session
        .analyze_files(
            &[FileAnalysisSource {
                location: FileLocation::Listed(path(location)),
                path: location.into(),
            }],
            &Default::default(),
            |_| Some(b"x".to_vec()),
        )
        .unwrap()
        .remove(0)
        .issues
        .remove(0);
    let task = Task::FixText {
        targets: vec![
            FixTextTarget::Web {
                issue: Box::new(web),
                url: "https://example.test".into(),
                detected_stack: None,
            },
            FixTextTarget::Code {
                issue: Box::new(code),
                framework: "fixture".into(),
            },
        ],
    };
    assert_eq!(
        session.begin(&begin(task, [])).unwrap(),
        Step::Done {
            done: Done::FixText(vec![
                "Synthetic module guidance for Sample finding".into(),
                "Synthetic module guidance".into(),
            ]),
        },
    );
    let target = BriefTarget {
        agent: "fixture".into(),
        attempt: 1,
        check_id: "code_scan.standin.rule".into(),
        description: "Fixture description".into(),
        detected_stack: None,
        likely_fix: None,
        locations: vec![
            BriefTargetLocation {
                path: location.into(),
                line: 2,
            },
            BriefTargetLocation {
                path: "another.txt".into(),
                line: 5,
            },
        ],
        severity: Severity::Low,
        site_url: "https://example.test".into(),
        title: "Fixture title".into(),
        why_now: None,
    };
    assert_eq!(
        session.begin(&begin(Task::Brief { target }, [])).unwrap(),
        Step::Done {
            done: Done::Brief(Brief {
                title: "SiteCMD: Sample finding".into(),
                body: "@fixture Please address the finding.\n\n## Where to look\n`app/fixture-findings.txt:2`\n`another.txt:5`\n\nOpen a pull request.".into(),
            }),
        },
    );
}

#[test]
fn standin_has_no_imports_and_exact_exports() {
    // Bug: An extra export or a host import can change the public Wasm boundary.
    use sitecmd_engine_host::embedded_module;
    use sitecmd_protocol::engine_abi::{decode_answer, ErrorAnswer, EXPORTS};

    let runtime = wasmtime::Engine::default();
    let module = wasmtime::Module::from_binary(&runtime, embedded_module()).unwrap();
    assert_eq!(module.imports().count(), 0);
    let mut exports = module
        .exports()
        .map(|export| {
            let memory = match export.ty() {
                wasmtime::ExternType::Memory(_) => true,
                wasmtime::ExternType::Func(_) => false,
                other => panic!("unexpected export type: {other:?}"),
            };
            (export.name().to_owned(), memory)
        })
        .collect::<Vec<_>>();
    exports.sort_unstable();
    let mut expected = EXPORTS
        .iter()
        .map(|&name| (name.to_owned(), name == "memory"))
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(exports, expected);

    #[derive(Deserialize)]
    struct MalformedCase {
        frame: Vec<u8>,
        answer: ErrorAnswer,
    }
    #[derive(Deserialize)]
    struct MalformedCorpus {
        malformed: MalformedCase,
    }
    let case = serde_json::from_str::<MalformedCorpus>(include_str!("../standin/corpus.json"))
        .unwrap()
        .malformed;
    let mut store = wasmtime::Store::new(&runtime, ());
    let guest = wasmtime::Instance::new(&mut store, &module, &[]).unwrap();
    let memory = guest.get_memory(&mut store, "memory").unwrap();
    let alloc = guest
        .get_typed_func::<u32, u32>(&mut store, "engine_alloc")
        .unwrap();
    let begin = guest
        .get_typed_func::<(u32, u32), u32>(&mut store, "session_begin")
        .unwrap();
    let free = guest
        .get_typed_func::<(u32, u32), ()>(&mut store, "engine_free")
        .unwrap();

    let length = case.frame.len().try_into().unwrap();
    let pointer = alloc.call(&mut store, length).unwrap();
    memory
        .write(&mut store, pointer as usize, &case.frame)
        .unwrap();
    let result = begin.call(&mut store, (pointer, length)).unwrap();
    let bytes = &memory.data(&store)[result as usize..];
    let answer_length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) + 4;
    let json = decode_answer(&bytes[..answer_length as usize]).unwrap();
    assert_eq!(
        serde_json::from_slice::<ErrorAnswer>(json).unwrap(),
        case.answer
    );
    free.call(&mut store, (result, answer_length)).unwrap();
}
