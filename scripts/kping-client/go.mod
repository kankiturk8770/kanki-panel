module kpclient

go 1.24

require mtuncore v0.0.0

// the app's own microtun client: kanki-app checked out next to kanki-panel
replace mtuncore => ../../../kanki-app/mtun-core
