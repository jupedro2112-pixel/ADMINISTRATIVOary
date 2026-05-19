/**
 * Publicista — control de gastos de publicidad.
 *
 * Por cada publicista se llevan dos cosas:
 *   - envios[]:  la plata que le mandamos día a día. Cada envío tiene un
 *                detalle (líneas API, u otros gastos) y un monto.
 *   - cierres[]: el cierre diario de su campaña — uno por día — con cuánto
 *                consumió, mensajes que llegaron, derivados, costo por
 *                mensaje. El % de conversión NO se guarda: se calcula
 *                (derivados / mensajes × 100).
 */
const mongoose = require('mongoose');

// Un envío de plata al publicista. Puede haber varios por día.
const envioSchema = new mongoose.Schema({
  id: { type: String, required: true },
  fecha: { type: String, default: '' },          // YYYY-MM-DD
  montoARS: { type: Number, default: 0, min: 0 },
  detalle: { type: String, default: '', trim: true, maxlength: 200 } // "líneas API", etc.
}, { _id: false });

// Cierre diario de la campaña del publicista. Uno por día.
const cierreDiaSchema = new mongoose.Schema({
  id: { type: String, required: true },
  fecha: { type: String, default: '' },          // YYYY-MM-DD
  consumoARS: { type: Number, default: 0, min: 0 },   // cuánto consumió
  mensajes: { type: Number, default: 0, min: 0 },     // mensajes que llegaron
  derivados: { type: Number, default: 0, min: 0 },    // cuántos fueron derivados
  costoMsjARS: { type: Number, default: 0, min: 0 },  // costo por mensaje (si cobra así)
  nota: { type: String, default: '', trim: true, maxlength: 200 }
}, { _id: false });

const publicistaSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  nombre: { type: String, default: '', trim: true, maxlength: 100 },
  notas: { type: String, default: '', maxlength: 500 },
  active: { type: Boolean, default: true },
  envios: { type: [envioSchema], default: [] },
  cierres: { type: [cierreDiaSchema], default: [] },
  createdBy: { type: String, default: '' }
}, { timestamps: true });

module.exports = mongoose.models['Publicista'] ||
  mongoose.model('Publicista', publicistaSchema);
