/**
 * Cierre mensual de gastos fijos. Foto congelada de los ítems al cerrar
 * el mes — sirve de historial y se puede tildar pagado.
 *
 * Al cerrar:
 *  - Se snapshotean los ítems vivos (GastoFijo) con sus montos del momento.
 *  - Los ítems vivos NO se borran: quedan como base del próximo mes y se
 *    pueden ajustar los montos antes del próximo cierre.
 *
 * El detalle compara cada concepto con el cierre anterior para mostrar
 * si el monto subió o bajó (delta).
 */
const mongoose = require('mongoose');

const closingItemSchema = new mongoose.Schema({
  concepto: { type: String, default: '' },
  moneda: { type: String, enum: ['pesos', 'usdt'], default: 'pesos' },
  monto: { type: Number, default: 0 },
  usdtRate: { type: Number, default: 0 },
  estructuraIdx: { type: Number, default: -1 },
  nota: { type: String, default: '' },
  montoARS: { type: Number, default: 0 }
}, { _id: false });

// Extras agregados DESPUÉS del cierre. No tocan el snapshot original
// (que queda congelado). Cada extra lleva su propio paid.
const extraItemSchema = new mongoose.Schema({
  id: { type: String, required: true },
  concepto: { type: String, default: '' },
  moneda: { type: String, enum: ['pesos', 'usdt'], default: 'pesos' },
  monto: { type: Number, default: 0 },
  usdtRate: { type: Number, default: 0 },
  estructuraIdx: { type: Number, default: -1 },
  nota: { type: String, default: '' },
  montoARS: { type: Number, default: 0 },
  paid: { type: Boolean, default: false },
  paidAt: { type: Date, default: null },
  paidBy: { type: String, default: '' },
  addedAt: { type: Date, default: Date.now },
  addedBy: { type: String, default: '' }
}, { _id: false });

const closingSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  periodLabel: { type: String, default: '', maxlength: 80 },
  closedAt: { type: Date, default: Date.now, index: true },
  closedBy: { type: String, default: '' },
  paid: { type: Boolean, default: false, index: true },
  paidAt: { type: Date, default: null },
  paidBy: { type: String, default: '' },
  items: { type: [closingItemSchema], default: [] },
  itemCount: { type: Number, default: 0 },
  estructuras: { type: [String], default: [] },
  totalARS: { type: Number, default: 0 },
  totalByEstructura: { type: [Number], default: [0, 0, 0] },
  totalSinEstructuraARS: { type: Number, default: 0 },
  extras: { type: [extraItemSchema], default: [] }
}, { timestamps: true });

module.exports = mongoose.models['GastoFijoClosing'] ||
  mongoose.model('GastoFijoClosing', closingSchema);
