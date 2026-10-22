use super::super::*;

fn source_file(relative_path: &str, content: &str) -> SourceFile {
    SourceFile {
        absolute_path: std::path::PathBuf::from(relative_path),
        relative_path: relative_path.to_string(),
        line_count: content.lines().count(),
        inline_rust_tests: false,
        content: content.to_string(),
    }
}

fn routes_file(content: &str) -> SourceFile {
    source_file("routes/api.php", content)
}

#[test]
fn group_config_array_protects_referenced_controllers() {
    let files = vec![routes_file(
        r#"<?php
Route::group(
['namespace' => 'App\Api\Controllers', 'prefix' => 'v1/accounts',
 'middleware' => ['auth:api,sanctum', 'throttle:60,1']],
static function (): void {
    Route::get('accounts/{account}', ['uses' => 'AccountController@show', 'as' => 'show']);
}
);
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    let status = protection
        .status_for("app/Api/Controllers/AccountController.php")
        .expect("controller should be routed"); // allow-expect: test assertion
    assert!(status.auth_protected);
    assert!(status.throttled);
}

#[test]
fn chained_middleware_group_protects_class_references() {
    let files = vec![routes_file(
        r#"<?php
Route::middleware(['auth'])->group(function () {
Route::post('/billing', [BillingController::class, 'store']);
});
Route::post('/contact', [ContactController::class, 'store']);
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    let billing = protection
        .status_for("app/Http/Controllers/BillingController.php")
        .expect("routed"); // allow-expect: test assertion
    assert!(billing.auth_protected);
    // Auth-protected means no hammerable surface, so `throttled` (no
    // reference reachable unauthenticated AND unthrottled) holds too.
    assert!(billing.throttled);
    let contact = protection
        .status_for("app/Http/Controllers/ContactController.php")
        .expect("routed"); // allow-expect: test assertion
    assert!(!contact.auth_protected);
    assert!(!contact.throttled);
}

#[test]
fn route_level_middleware_chain_protects_a_single_registration() {
    let files = vec![routes_file(
        r#"<?php
Route::post('/settings', [SettingsController::class, 'update'])->middleware('auth');
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    let status = protection
        .status_for("app/Http/Controllers/SettingsController.php")
        .expect("routed"); // allow-expect: test assertion
    assert!(status.auth_protected);
}

#[test]
fn one_public_reference_makes_the_controller_unprotected() {
    let files = vec![routes_file(
        r#"<?php
Route::middleware(['auth'])->group(function () {
Route::get('/billing', [BillingController::class, 'index']);
});
Route::post('/billing/webhook', [BillingController::class, 'webhook']);
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    let status = protection
        .status_for("app/Http/Controllers/BillingController.php")
        .expect("routed"); // allow-expect: test assertion
    assert!(!status.auth_protected);
}

#[test]
fn guest_middleware_and_auth_like_uris_grant_nothing() {
    // 'guest' must not read as auth, and a URI segment like 'auth/login'
    // must not turn a middleware-free registration into a protected one.
    let files = vec![routes_file(
        r#"<?php
Route::group(['middleware' => ['guest']], function () {
Route::post('/login', [LoginController::class, 'store']);
});
Route::get('auth/callback', [OauthController::class, 'callback'])->middleware('web');
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    assert!(
        !protection
            .status_for("app/Http/Controllers/LoginController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
    assert!(
        !protection
            .status_for("app/Http/Controllers/OauthController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
}

#[test]
fn route_names_and_group_prefixes_do_not_count_as_middleware() {
    let files = vec![routes_file(
        r#"<?php
Route::post('/login', [LoginController::class, 'store'])->middleware('web')->name('auth.login');
Route::group(['as' => 'auth.', 'middleware' => ['web']], function () {
    Route::post('/password/email', [PasswordController::class, 'email']);
});
Route::group(['middleware' => ['web'], 'prefix' => 'api'], function () {
    Route::post('/feedback', [FeedbackController::class, 'store']);
});
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    for controller in [
        "app/Http/Controllers/LoginController.php",
        "app/Http/Controllers/PasswordController.php",
    ] {
        let status = protection.status_for(controller).expect("routed"); // allow-expect: test assertion
        assert!(
            !status.auth_protected,
            "{controller}: a route name or group prefix is not auth middleware"
        );
    }
    let feedback = protection
        .status_for("app/Http/Controllers/FeedbackController.php")
        .expect("routed"); // allow-expect: test assertion
    assert!(
        !feedback.throttled,
        "a 'prefix' => 'api' next to the middleware key is not the api middleware group"
    );
}

#[test]
fn nested_groups_inherit_outer_protection() {
    let files = vec![routes_file(
        r#"<?php
Route::middleware(['auth:sanctum'])->group(function () {
Route::group(['prefix' => 'admin'], function () {
    Route::delete('/users/{id}', [UserAdminController::class, 'destroy']);
});
});
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    assert!(
        protection
            .status_for("app/Http/Controllers/UserAdminController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
}

#[test]
fn uri_braces_inside_strings_do_not_break_scope_tracking() {
    let files = vec![routes_file(
        r#"<?php
Route::middleware(['auth'])->group(function () {
Route::get('/accounts/{account}/items/{item}', [ItemController::class, 'show']);
Route::post('/accounts/{account}/items', [ItemController::class, 'store']);
});
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    assert!(
        protection
            .status_for("app/Http/Controllers/ItemController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
}

#[test]
fn bootstrap_api_group_definition_protects_the_whole_api_routes_file() {
    let files = vec![
        source_file(
            "bootstrap/app.php",
            r#"<?php
return Application::configure(basePath: dirname(__DIR__))
->withRouting(
    web: __DIR__ . '/../routes/web.php',
    api: __DIR__ . '/../routes/api.php',
)
->withMiddleware(function (Middleware $middleware): void {
    $middleware->group('api',
        [
            AcceptHeaders::class,
            // EnsureFrontendRequestsAreStateful::class,
            'auth:api',
            Binder::class,
        ]
    );
    $middleware->appendToGroup('user-full-auth', [
        Authenticate::class,
        MFAMiddleware::class,
    ]);
})->create();
"#,
        ),
        routes_file(
            r#"<?php
Route::group(
['namespace' => 'App\Api\Controllers', 'prefix' => 'v1/autocomplete'],
static function (): void {
    Route::get('accounts', ['uses' => 'AccountController@accounts', 'as' => 'accounts']);
}
);
"#,
        ),
        source_file(
            "routes/web.php",
            r#"<?php
Route::group(['middleware' => ['user-full-auth']], function () {
Route::get('/accounts', ['uses' => 'AccountWebController@index', 'as' => 'accounts.index']);
});
Route::post('/contact', [ContactController::class, 'store']);
"#,
        ),
    ];
    let protection = collect_laravel_route_protection(&files);
    // api.php reference: protected by the file's base 'api' group.
    assert!(
        protection
            .status_for("app/Api/Controllers/AccountController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
    assert!(protection.routes_file_is_auth_protected("routes/api.php"));
    // web.php reference under the custom group whose definition contains
    // Authenticate::class: protected by group-name resolution.
    assert!(
        protection
            .status_for("app/Http/Controllers/AccountWebController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
    assert!(protection.routes_file_is_auth_protected("routes/web.php"));
    assert!(
        !protection
            .status_for("app/Http/Controllers/ContactController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
}

#[test]
fn without_middleware_revokes_the_file_base_protection() {
    // Firefly's public cron endpoint: inside the auth-protected api.php
    // but explicitly opted out of the 'api' middleware group.
    let files = vec![
        source_file(
            "bootstrap/app.php",
            r#"<?php
$middleware->group('api', ['auth:api', Binder::class]);
"#,
        ),
        routes_file(
            r#"<?php
Route::get('cron/{cliToken}', [CronController::class, 'cron'])
->name('index')
->withoutMiddleware(['api']);
Route::get('accounts', [AccountController::class, 'index']);
"#,
        ),
    ];
    let protection = collect_laravel_route_protection(&files);
    assert!(
        !protection
            .status_for("app/Api/Controllers/CronController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
    assert!(
        protection
            .status_for("app/Api/Controllers/AccountController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
}

#[test]
fn commented_out_middleware_lines_grant_nothing() {
    let files = vec![source_file(
        "routes/web.php",
        r#"<?php
// Route::get('/authorize', ['uses' => 'AuthorizationController@authorize', 'middleware' => 'auth']);
Route::post('/token', [TokenController::class, 'issue']);
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    // The commented registration must not register its controller...
    assert!(protection
        .status_for("app/Http/Controllers/AuthorizationController.php")
        .is_none());
    assert!(
        !protection
            .status_for("app/Http/Controllers/TokenController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
}

#[test]
fn custom_middleware_class_that_rejects_guests_grants_auth_transitively() {
    let files = vec![
        source_file(
            "bootstrap/app.php",
            r#"<?php
$middleware->appendToGroup('admin', [IsAdmin::class, Range::class]);
$middleware->appendToGroup('visitors', [RedirectIfAuthenticated::class]);
"#,
        ),
        source_file(
            "app/Http/Middleware/IsAdmin.php",
            r#"<?php
class IsAdmin
{
public function handle($request, Closure $next)
{
    if (Auth::guard()->guest()) {
        return redirect()->route('login');
    }
    return $next($request);
}
}
"#,
        ),
        source_file(
            "app/Http/Middleware/RedirectIfAuthenticated.php",
            r#"<?php
class RedirectIfAuthenticated
{
public function handle($request, Closure $next)
{
    if (Auth::guard()->check()) {
        return redirect('/home');
    }
    return $next($request);
}
}
"#,
        ),
        source_file(
            "routes/web.php",
            r#"<?php
Route::group(['middleware' => 'admin'], function () {
Route::get('/settings', ['uses' => 'ConfigurationController@index']);
});
Route::group(['middleware' => 'visitors'], function () {
Route::post('/register', ['uses' => 'RegisterController@store']);
});
"#,
        ),
    ];
    let protection = collect_laravel_route_protection(&files);
    assert!(
        protection
            .status_for("app/Http/Controllers/Admin/ConfigurationController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
    assert!(
        !protection
            .status_for("app/Http/Controllers/Auth/RegisterController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
}

#[test]
fn legacy_kernel_middleware_groups_are_resolved() {
    let files = vec![
        source_file(
            "app/Http/Kernel.php",
            r#"<?php
class Kernel extends HttpKernel
{
protected $middlewareGroups = [
    'web' => [
        \App\Http\Middleware\EncryptCookies::class,
        \Illuminate\Session\Middleware\StartSession::class,
    ],
    'api' => [
        'throttle:api',
        \Illuminate\Routing\Middleware\SubstituteBindings::class,
    ],
];
}
"#,
        ),
        routes_file(
            r#"<?php
Route::post('/search', [SearchController::class, 'search']);
"#,
        ),
    ];
    let protection = collect_laravel_route_protection(&files);
    let status = protection
        .status_for("app/Http/Controllers/SearchController.php")
        .expect("routed"); // allow-expect: test assertion
                           // The default api group throttles but does not authenticate.
    assert!(status.throttled);
    assert!(!status.auth_protected);
    assert!(!protection.routes_file_is_auth_protected("routes/api.php"));
}

#[test]
fn invokable_controller_inside_nested_chained_groups_is_protected() {
    let files = vec![routes_file(
        r#"<?php
use App\Http\Controllers\API\ScrobbleController;

Route::prefix('api')
->middleware('api')
->group(static function (): void {
    Route::get('ping', static fn () => null);

    Route::middleware('auth')->group(static function (): void {
        Route::post('songs/{song}/scrobble', ScrobbleController::class);
    });
});
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    let status = protection
        .status_for("app/Http/Controllers/API/ScrobbleController.php")
        .expect("routed"); // allow-expect: test assertion
    assert!(status.auth_protected);
}

#[test]
fn endpoint_map_arrays_inherit_file_wide_protection() {
    let files = vec![source_file(
        "routes/subsonic.php",
        r#"<?php
use App\Http\Controllers\Subsonic\GetPlaylistsController;
use App\Http\Controllers\Subsonic\PingController;

$commonRoutes = [
'ping' => PingController::class,
'getPlaylists' => GetPlaylistsController::class,
];

Route::prefix('rest')
->middleware([NormalizeSubsonicArrayParams::class, AuthenticateSubsonicRequests::class])
->group(static function () use ($commonRoutes): void {
    foreach ($commonRoutes as $endpoint => $controller) {
        Route::match(['get', 'post'], "{$endpoint}{format?}", $controller);
    }
});
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    let status = protection
        .status_for("app/Http/Controllers/Subsonic/GetPlaylistsController.php")
        .expect("routed"); // allow-expect: test assertion
    assert!(status.auth_protected);
}

#[test]
fn middleware_alias_resolving_to_authenticate_class_grants_auth() {
    // The koel web.base.php shape: 'audio.auth' aliases an Authenticate*
    // class, and download/play routes sit behind that alias.
    let files = vec![
        source_file(
            "bootstrap/app.php",
            r#"<?php
$middleware->alias([
'audio.auth' => AuthenticateAudioRequests::class,
'embeds.enabled' => EnsureEmbedsEnabled::class,
]);
"#,
        ),
        source_file(
            "routes/web.php",
            r#"<?php
Route::middleware('audio.auth')->group(static function (): void {
Route::get('play/{song}/{transcode?}', PlayController::class);
});
Route::middleware('embeds.enabled')->group(static function (): void {
Route::get('embeds/{embed}', EmbedController::class);
});
"#,
        ),
    ];
    let protection = collect_laravel_route_protection(&files);
    assert!(
        protection
            .status_for("app/Http/Controllers/PlayController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
    // A non-auth alias grants nothing.
    assert!(
        !protection
            .status_for("app/Http/Controllers/EmbedController.php")
            .expect("routed") // allow-expect: test assertion
            .auth_protected
    );
}

#[test]
fn mixed_throttled_public_and_authed_routes_are_not_hammerable() {
    let files = vec![routes_file(
        r#"<?php
Route::middleware('throttle:10,1')->group(static function (): void {
Route::post('invitations/accept', [UserInvitationController::class, 'accept']);
});
Route::middleware('auth')->group(static function (): void {
Route::post('invitations', [UserInvitationController::class, 'invite']);
});
"#,
    )];
    let protection = collect_laravel_route_protection(&files);
    let status = protection
        .status_for("app/Http/Controllers/API/UserInvitationController.php")
        .expect("routed"); // allow-expect: test assertion
    assert!(!status.auth_protected);
    assert!(status.throttled);
}

#[test]
fn non_laravel_projects_resolve_nothing() {
    let files = vec![source_file(
        "src/routes/users.ts",
        "router.post('/users', createUser);",
    )];
    let protection = collect_laravel_route_protection(&files);
    assert!(protection
        .status_for("src/controllers/UserController.php")
        .is_none());
}
