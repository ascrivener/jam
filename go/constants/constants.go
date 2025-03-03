package constants

const NumValidators int = 1023

const TwoThirdsNumValidators int = 2 * NumValidators / 3

const NumValidatorSafetyThreshold int = TwoThirdsNumValidators + 1

const OneThirdNumValidators int = NumValidators / 3

const NumTicketEntries int = 2

const NumTimeslotsPerEpoch int = 600

const TicketSubmissionEndingSlotPhaseNumber int = 500

const NumCores int = 341

const AuthorizerQueueLength int = 80

const MaxItemsInAuthorizationsPool int = 8

const ValidatorCoreAssignmentsRotationPeriodInTimeslots int = 10

const UnavailableWorkTimeoutTimeslots int = 5

const MaxWorkItemsInPackage int = 4

const ServiceCodeMaxSize int = 4000000

const ServiceMinimumBalance int = 100 // Bs

const ServiceMinimumBalancePerItem int = 10 // Bi

const ServiceMinimumBalancePerOctet int = 1 // Bl
