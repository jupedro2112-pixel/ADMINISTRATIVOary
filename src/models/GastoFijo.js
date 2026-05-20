/**
 * Gasto fijo mensual — luz, agua, alquileres, comisiones, etc.
 *
 * Cada gasto se carga en su moneda (pesos o USDT). Para sumar entre gastos
 * en USDT y en pesos, el reporte convierte usando el usdtRate de cada
 * gasto y produce un total mensual en ARS.
 *
 * Las "estructuras" son una lista fija de 3 (configurable, ver Config key
 * `gastos_fijos_estructuras`). Cada gasto puede pertenecer a una estructura
 * (estructuraIdx 0..2) o quedar sin estructura (-1). Sirve para agrupar
 * alquileres + comisiones por unidad/local.
 */
const mongoose = require('mongoose');

const gastoFijoSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  concepto: { type: String, default: '', trim: true, maxlength: 100 },
  moneda: { type: String, enum: ['pesos', 'usdt'], default: 'pesos' },
  monto: { type: Number, default: 0, min: 0 },          // en la moneda elegida
  usdtRate: { type: Number, default: 0, min: 0 },        // ARS por 1 USDT (si moneda='usdt')
  // -1 = sin estructura; 0/1/2 = índice en la lista de 3 estructuras.
  estructuraIdx: { type: Number, default: -1, min: -1, max: 2 },
  nota: { type: String, default: '', trim: true, maxlength: 200 },
  active: { type: Boolean, default: true },
  createdBy: { type: String, default: '' }
}, { timestamps: true });

module.exports = mongoose.models['GastoFijo'] ||
  mongoose.model('GastoFijo', gastoFijoSchema);
