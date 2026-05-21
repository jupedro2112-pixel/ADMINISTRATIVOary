/**
 * Gasto interno mensual — igual concepto que GastoFijo pero categoría aparte.
 * Acceso protegido con PIN propio (100) — separado de Publicidad / Gastos fijos.
 *
 * Mismo schema que GastoFijo: concepto, moneda (pesos/USDT con cotización),
 * monto, 3 estructuras editables (índice 0..2 o -1 para sin estructura), nota.
 */
const mongoose = require('mongoose');

const gastoInternoSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  concepto: { type: String, default: '', trim: true, maxlength: 100 },
  moneda: { type: String, enum: ['pesos', 'usdt'], default: 'pesos' },
  monto: { type: Number, default: 0, min: 0 },
  usdtRate: { type: Number, default: 0, min: 0 },
  estructuraIdx: { type: Number, default: -1, min: -1, max: 2 },
  nota: { type: String, default: '', trim: true, maxlength: 200 },
  active: { type: Boolean, default: true },
  createdBy: { type: String, default: '' }
}, { timestamps: true });

module.exports = mongoose.models['GastoInterno'] ||
  mongoose.model('GastoInterno', gastoInternoSchema);
