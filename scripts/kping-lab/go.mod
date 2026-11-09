module kplab

go 1.24

require mtuncore v0.0.0

// the app's own microtun client (for the comparison): kanki-app checked out next to kanki-panel
replace mtuncore => ../../../kanki-app/mtun-core
