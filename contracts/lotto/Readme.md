# Lotto

Lotto is a platform that enables lottery creator to easily create their lotteries and get a share from the earning.

## Lotto agents:

- Manager: Sets the community pool address and sets the protocol and creator comissions. The manger can also withdraw the protocol rewards.
- Creator: The creator creates lotteries and gets to specify the duration, the token and price of a ticket, number of winners, and the commission cut that goes to the community pool
- Player: Plays on one or many lotteries

## Contract Flow

- The contract is instantiated with a manager
- The manager sets the commission rates
- A creator creates a lotto instance -> This action will trigger a job schedule in Nois chain to request a random beacon the moment the lottery closes
- Players buy tickets in this lotto instance
- The lotto is over
- Nois sends the random beacon and settles the winners and distributes the funds to the winners, the creator and the community pool. The protocol commission stays in the contract until claimed by the manager.
