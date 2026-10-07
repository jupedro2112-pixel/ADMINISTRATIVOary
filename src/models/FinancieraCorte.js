/**
 * Corte de la financiera — sección FINANCIERA.
 *
 * Lo bajado en los cierres diarios de Ganamos + Publicidad se manda a la
 * financiera, que cotiza y cierra todos los días a las 13 hs. Cada corte
 * registra a qué precio cotizó el USDT y cuántos USDT se recibieron.
 *
 * Los cierres van de 00 a 00 y los cortes son a las 13 hs, así que no se
 * emparejan día a día: se lleva como cuenta corriente.
 *   la financiera debe = saldo inicial + Σ bajado − Σ (usdtRecibidos × usdtRate)
 */
const mongoose = require('mongoose');

const financieraCorteSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  // YYYY-MM-DD (hora Argentina) del día del corte.
  dateKey: { type: String, required: true, index: true },
  // Precio del USDT en ARS al que cotizó la financiera.
  usdtRate: { type: Number, required: true, min: 0 },
  // USDT efectivamente recibidos en el corte.
  usdtRecibidos: { type: Number, required: true, min: 0 },
  nota: { type: String, default: '', trim: true, maxlength: 300 },
  createdBy: { type: String, default: '' },
  updatedBy: { type: String, default: '' }
}, { timestamps: true });

module.exports = mongoose.models['FinancieraCorte'] ||
  mongoose.model('FinancieraCorte', financieraCorteSchema);
