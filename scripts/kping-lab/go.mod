module kplab

go 1.24

require (
	kpingcore v0.0.0
	mtuncore v0.0.0
)

// the app's own clients: kanki-app checked out next to kanki-panel
replace (
	kpingcore => ../../../kanki-app/kping-core
	mtuncore => ../../../kanki-app/mtun-core
)
