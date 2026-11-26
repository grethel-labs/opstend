# OpsTend and Zorec

OpsTend is the Grethel Labs product for self-hosted infrastructure operations.
The lowercase **opstend** wordmark sits alongside **excaliplant**. In prose,
use **OpsTend** and spell the optional assistant **Zorec** with one `r`.

## Marks

The OpsTend mark combines two server trays and a teal return arrow. The trays
represent the managed host. The arrow represents observing its state and
correcting deviations within configured limits. Its angled return echoes the
open contour of the Grethel Labs flask. Ink (`#111827`), Off-White (`#F7F8FA`)
and Teal (`#2DB8A8`) come from the official palette. The README, sign-in page
and console header show the mark with the **by Grethel Labs** byline. The
favicon uses the mark on its own. [Grethel Labs brand kit](https://github.com/grethel-labs/.github/tree/main/brand-kit)

The signet has [light](../webapp/public/brand/opstend.svg) and
[dark](../webapp/public/brand/opstend-dark.svg) SVG versions. The README and
admin console follow the system preference.

## Zorec's gestures

Zorec is a wide, petrol-coloured onboard computer with bevelled lower corners,
a dark display and an ice-blue port. The housing stays fixed. Eye shapes and
small display or port details express the current state.

[zorec.svg](../webapp/public/brand/zorec.svg) contains 14 gestures, each in
light and dark. Its default view is light neutral. Refer to the other views
with fragments such as `#dark-verifying`. In the UI, the adjacent status or
result text carries the meaning for assistive technology.

| Gesture | Light | Dark | Context |
| --- | --- | --- | --- |
| Neutral | ![](../webapp/public/brand/zorec.svg#light-neutral) | ![](../webapp/public/brand/zorec.svg#dark-neutral) | Navigation and idle state |
| Listening | ![](../webapp/public/brand/zorec.svg#light-listening) | ![](../webapp/public/brand/zorec.svg#dark-listening) | A question is being typed |
| Thinking | ![](../webapp/public/brand/zorec.svg#light-thinking) | ![](../webapp/public/brand/zorec.svg#dark-thinking) | A question or background request is pending |
| Answered | ![](../webapp/public/brand/zorec.svg#light-answered) | ![](../webapp/public/brand/zorec.svg#dark-answered) | Zorec has returned an answer |
| Missing data | ![](../webapp/public/brand/zorec.svg#light-missing-data) | ![](../webapp/public/brand/zorec.svg#dark-missing-data) | Advice gap or empty model scan |
| Limit reached | ![](../webapp/public/brand/zorec.svg#light-limit) | ![](../webapp/public/brand/zorec.svg#dark-limit) | The advice budget is exhausted |
| Offline | ![](../webapp/public/brand/zorec.svg#light-offline) | ![](../webapp/public/brand/zorec.svg#dark-offline) | Provider unavailable or runtime disabled |
| Setup | ![](../webapp/public/brand/zorec.svg#light-setup) | ![](../webapp/public/brand/zorec.svg#dark-setup) | Provider setup is open or needed |
| Verifying | ![](../webapp/public/brand/zorec.svg#light-verifying) | ![](../webapp/public/brand/zorec.svg#dark-verifying) | Provider settings are saving or being verified |
| Scanning | ![](../webapp/public/brand/zorec.svg#light-scanning) | ![](../webapp/public/brand/zorec.svg#dark-scanning) | A model scan is queued or running |
| Selection | ![](../webapp/public/brand/zorec.svg#light-selection) | ![](../webapp/public/brand/zorec.svg#dark-selection) | Models are available to choose from |
| Awaiting download | ![](../webapp/public/brand/zorec.svg#light-awaiting-download) | ![](../webapp/public/brand/zorec.svg#dark-awaiting-download) | A local model is staged for installation |
| Failed | ![](../webapp/public/brand/zorec.svg#light-failed) | ![](../webapp/public/brand/zorec.svg#dark-failed) | The setup view shows an error |
| Ready | ![](../webapp/public/brand/zorec.svg#light-ready) | ![](../webapp/public/brand/zorec.svg#dark-ready) | Provider runtime enabled with a selected model |

## Interface tokens

| Role | Light | Dark |
| --- | --- | --- |
| Canvas | `#f7fbfa` | `#111827` |
| Panel | `#ffffff` | `#1b3038` |
| Secondary surface | `#e8f5f1` | `#233c43` |
| Text | `#172e32` | `#f7f8fa` |
| Muted text | `#3f6261` | `#bfd1d3` |
| Divider | `#c9ddd7` | `#315058` |
| Primary action and focus | `#0b7168` | `#2db8a8` |

[brand.css](../webapp/src/brand.css) defines the tokens and follows the
system light or dark preference. [styles.css](../webapp/src/styles.css)
defines the shared navigation, 10 px controls, 14 px panels, and status
badges. Use system sans for interface text and monospace for commands,
versions and checksums. Show a text label alongside status colours and give
keyboard focus a visible outline.

Current operator commands use `./opstend` on the controller and `opstend-host`
on the server. Existing scripts can still call the old command names.
Installed host paths, service names, accounts and the signed wheel identity
keep their existing names so upgrades continue to use the same data and trust
configuration. See the [upgrade notes](release.md#upgrading-from-steward).
