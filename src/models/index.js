/**
 * Índice de Modelos — herramienta de Cierres.
 * Solo los modelos que consume config/database.js.
 */
module.exports = {
  User: require('./User'),
  Message: require('./Message'),
  Command: require('./Command'),
  Config: require('./Config'),
  RefundClaim: require('./RefundClaim'),
  PlayerStats: require('./PlayerStats'),
  DailyAppOpen: require('./DailyAppOpen')
};
