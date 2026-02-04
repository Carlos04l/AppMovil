package com.example.guiadragoncity.data

import androidx.compose.ui.graphics.Color

// 1. Elementos básicos
data class Elemento(
    val nombre: String,
    val color: Color,
    val fuerteContra: List<String>,
    val debilContra: List<String>,
    val habitat: String
)

val ELEMENTOS = listOf(
    Elemento("Terra", Color(0xFF8B4513), listOf("Eléctrico", "Metal"), listOf("Hielo", "Naturaleza"), "Hábitat Tierra"),
    Elemento("Llama", Color(0xFFFF4500), listOf("Naturaleza", "Hielo"), listOf("Mar", "Terra"), "Hábitat Fuego"),
    Elemento("Mar", Color(0xFF1E90FF), listOf("Llama", "Terra"), listOf("Eléctrico"), "Hábitat Agua"),
    Elemento("Naturaleza", Color(0xFF228B22), listOf("Terra", "Agua"), listOf("Llama"), "Hábitat Planta"),
    Elemento("Eléctrico", Color(0xFFFFFF00), listOf("Mar", "Metal"), listOf("Terra"), "Hábitat Eléctrico"),
    Elemento("Hielo", Color(0xFFADD8E6), listOf("Naturaleza", "Terra"), listOf("Llama", "Eléctrico"), "Hábitat Hielo"),
    Elemento("Metal", Color(0xFFC0C0C0), listOf("Hielo", "Oscuro"), listOf("Fuego", "Eléctrico"), "Hábitat Metal")
)

// 2. Dragones básicos para principiantes
data class Dragon(
    val nombre: String,
    val elementos: List<String>,
    val descripcion: String
)

val DRAGONES_BASICOS = listOf(
    Dragon("Terra", listOf("Terra"), "Dragón básico de tierra. Fuerte contra eléctricos."),
    Dragon("Llama", listOf("Llama"), "Dragón de fuego. Muy útil contra naturaleza."),
    Dragon("Mar", listOf("Mar"), "Dragón de agua. Apaga dragones de fuego."),
    Dragon("Flor", listOf("Naturaleza"), "Dragón planta. Fácil de obtener."),
    Dragon("Eléctrico", listOf("Eléctrico"), "Ataques rápidos y eléctricos."),
    Dragon("Hielo", listOf("Hielo"), "Congela enemigos en batalla."),
    Dragon("Metal", listOf("Metal"), "Muy resistente a daños físicos.")
)

// 3. Combinaciones fáciles de cría
data class CombinacionCria(
    val padres: String,
    val resultado: String,
    val tiempo: String,
    val elementos: List<String>
)

val COMBINACIONES_FACILES = listOf(
    CombinacionCria("Terra + Llama", "Volcano", "36 horas", listOf("Terra", "Llama")),
    CombinacionCria("Terra + Mar", "Mud", "36 horas", listOf("Terra", "Mar")),
    CombinacionCria("Llama + Naturaleza", "Firebird", "48 horas", listOf("Llama", "Naturaleza")),
    CombinacionCria("Mar + Naturaleza", "Coral", "36 horas", listOf("Mar", "Naturaleza")),
    CombinacionCria("Mar + Eléctrico", "Storm", "48 horas", listOf("Mar", "Eléctrico"))
)

// 4. Consejos para nuevos jugadores
data class Consejo(
    val titulo: String,
    val texto: String
)

val CONSEJOS = listOf(
    Consejo("Prioriza granjas", "Construye y mejora granjas de comida y oro lo antes posible."),
    Consejo("Ahorra gemas", "No las gastes en cosas pequeñas, guárdalas para eventos o más criaderos."),
    Consejo("Únete a alianza", "Te dan bonos diarios y ayuda en rescates."),
    Consejo("Cría híbridos", "Son mucho más fuertes que los elementales puros."),
    Consejo("Eventos diarios", "Siempre participa para obtener recompensas gratis.")
)