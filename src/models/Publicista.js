/**
 * Publicista / agencia — control de gastos de publicidad.
 *
 * Config por agencia:
 *   - moneda:        'pesos' o 'usdt'. Si es usdt, usdtRate convierte a ARS.
 *   - comisionTipo:  cómo cobra la agencia su comisión:
 *       'porcentaje' → un % sobre el consumo (inversión de pauta).
 *       'por_mensaje' → un monto por cada mensaje recibido.
 *   - comisionValor: el % (si porcentaje) o el costo por mensaje (si por_mensaje).
 *
 * Por cada agencia se llevan:
 *   - envios[]:  la plata que le mandamos día a día, con detalle del gasto.
 *   - cierres[]: el cierre diario de campaña — uno por día — con cuánto
 *                consumió, mensajes que llegaron y derivados.
 *
 * La comisión y el % de conversión NO se guardan: se calculan en el front
 * a partir de la config de la agencia (la lógica sigue siempre la misma).
 */
const mongoose = require('mongoose');

// Un envío de plata a la agencia. Puede haber varios por día.
const envioSchema = new mongoose.Schema({
  id: { type: String, required: true },
  fecha: { type: String, default: '' },          // YYYY-MM-DD
  montoARS: { type: Number, default: 0, min: 0 }, // monto en la moneda de la agencia
  detalle: { type: String, default: '', trim: true, maxlength: 200 } // "líneas API", etc.
}, { _id: false });

// Cierre diario de la campaña de la agencia. Uno por día.
const cierreDiaSchema = new mongoose.Schema({
  id: { type: String, required: true },
  fecha: { type: String, default: '' },              // YYYY-MM-DD
  consumoARS: { type: Number, default: 0, min: 0 },   // cuánto consumió (en la moneda de la agencia)
  mensajes: { type: Number, default: 0, min: 0 },     // mensajes que llegaron
  derivados: { type: Number, default: 0, min: 0 },    // cuántos fueron derivados
  nota: { type: String, default: '', trim: true, maxlength: 200 }
}, { _id: false });

const publicistaSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  nombre: { type: String, default: '', trim: true, maxlength: 100 },
  notas: { type: String, default: '', maxlength: 500 },
  active: { type: Boolean, default: true },

  // === Config de la agencia ===
  moneda: { type: String, enum: ['pesos', 'usdt'], default: 'pesos' },
  usdtRate: { type: Number, default: 0, min: 0 },     // ARS por 1 USDT (si moneda='usdt')
  comisionTipo: { type: String, enum: ['porcentaje', 'por_mensaje'], default: 'porcentaje' },
  comisionValor: { type: Number, default: 0, min: 0 }, // % si porcentaje, costo/msj si por_mensaje

  envios: { type: [envioSchema], default: [] },
  cierres: { type: [cierreDiaSchema], default: [] },
  createdBy: { type: String, default: '' }
}, { timestamps: true });

module.exports = mongoose.models['Publicista'] ||
  mongoose.model('Publicista', publicistaSchema);
