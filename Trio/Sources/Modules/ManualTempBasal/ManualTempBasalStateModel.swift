import Observation
import SwiftUI

extension ManualTempBasal {
    @Observable final class StateModel: BaseStateModel<Provider> {
        @ObservationIgnored @Injected() var apsManager: APSManager!
        var rate: Decimal = 0
        var maximumBasalRate: Decimal = 0
        var durationIndex = 0

        let durationValues = stride(from: 30.0, to: 720.1, by: 30.0).map { $0 }

        var rateIsValid: Bool { rate >= 0 && rate <= maximumBasalRate }

        override func subscribe() {
            maximumBasalRate = settingsManager.pumpSettings.maxBasal
        }

        func cancel() {
            Task {
                await apsManager.enactTempBasal(rate: 0, duration: 0)
                showModal(for: nil)
            }
        }

        func enact() {
            guard rateIsValid else { return }
            let requestedRate = rate
            let requestedDuration = durationValues[durationIndex]
            Task {
                await apsManager.enactTempBasal(rate: Double(requestedRate), duration: requestedDuration * 60)
                showModal(for: nil)
            }
        }
    }
}
