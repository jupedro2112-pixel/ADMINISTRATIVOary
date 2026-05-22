/**
 * Cierre mensual de gastos internos. Igual lógica que GastoFijoClosing
 * pero colección aparte (categoría con PIN propio: 100).
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
  totalSinEstructuraARS: { type: Number, default: 0 }
}, { timestamps: true });

module.exports = mongoose.models['GastoInternoClosing'] ||
  mongoose.model('GastoInternoClosing', closingSchema);
