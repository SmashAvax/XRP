/* global artifacts */
require('dotenv').config({ path: '../.env' })
const BEP20Smashnado = artifacts.require('BEP20Smashnado')
const Verifier = artifacts.require('Verifier')
const hasherContract = artifacts.require('Hasher')


module.exports = function(deployer, network, accounts) {
  return deployer.then(async () => {
    const { MERKLE_TREE_HEIGHT, BEP20_TOKEN, TOKEN_AMOUNT_O } = process.env
    const verifier = await Verifier.deployed()
    const hasherInstance = await hasherContract.deployed()
    await BEP20Smashnado.link(hasherContract, hasherInstance.address)
    let token = BEP20_TOKEN
    const smashnado = await deployer.deploy(
      BEP20Smashnado,
      verifier.address,
      TOKEN_AMOUNT_O,
      MERKLE_TREE_HEIGHT,
      accounts[0],
      token,
    )
    console.log('XRPSmascash\'s address ', smashnado.address)
  })
}
