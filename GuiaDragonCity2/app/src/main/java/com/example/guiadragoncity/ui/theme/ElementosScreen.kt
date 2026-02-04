package com.example.guiadragoncity

import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.*
import com.example.guiadragoncity.data.ELEMENTOS   // ← Este import es clave

@Composable
fun ElementosScreen() {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        item {
            Text(
                text = "Elementos Básicos de Dragon City",
                style = MaterialTheme.typography.headlineMedium
            )
        }

        items(ELEMENTOS) { elemento ->
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(elemento.nombre, style = MaterialTheme.typography.titleLarge)
                    Text("Fuerte contra: ${elemento.fuerteContra.joinToString()}")
                    Text("Débil contra: ${elemento.debilContra.joinToString()}")
                    Text("Hábitat: ${elemento.habitat}")
                }
            }
        }
    }
}