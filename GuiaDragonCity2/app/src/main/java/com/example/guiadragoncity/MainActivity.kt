package com.example.guiadragoncity

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lightbulb
import androidx.compose.material.icons.filled.Pets
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.TipsAndUpdates
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.guiadragoncity.data.ELEMENTOS
import com.example.guiadragoncity.ui.theme.GuiaDragonCityTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            GuiaDragonCityTheme {
                MainScreen()
            }
        }
    }
}

@Composable
fun MainScreen() {
    val navController = rememberNavController()

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = { BottomNavigationBar(navController) }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Home.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Screen.Home.route) { HomeScreen() }
            composable(Screen.Elementos.route) { ElementosScreen() }
            composable(Screen.Dragones.route) { DragonesScreen() }
            composable(Screen.Cria.route) { CriaScreen() }
            composable(Screen.Consejos.route) { ConsejosScreen() }
        }
    }
}

@Composable
fun BottomNavigationBar(navController: NavController) {
    val items = listOf(
        Screen.Home,
        Screen.Elementos,
        Screen.Dragones,
        Screen.Cria,
        Screen.Consejos
    )

    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = navBackStackEntry?.destination

    NavigationBar {
        items.forEach { screen ->
            NavigationBarItem(
                icon = { Icon(screen.icon, contentDescription = screen.title) },
                label = { Text(screen.title) },
                selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true,
                onClick = {
                    navController.navigate(screen.route) {
                        popUpTo(navController.graph.findStartDestination().id) {
                            saveState = true
                        }
                        launchSingleTop = true
                        restoreState = true
                    }
                }
            )
        }
    }
}

sealed class Screen(val route: String, val title: String, val icon: androidx.compose.ui.graphics.vector.ImageVector) {
    data object Home : Screen("home", "Inicio", Icons.Default.Home)
    data object Elementos : Screen("elementos", "Elementos", Icons.Default.Lightbulb)
    data object Dragones : Screen("dragones", "Dragones", Icons.Default.Pets)
    data object Cria : Screen("cria", "Cría", Icons.Default.Science)
    data object Consejos : Screen("consejos", "Consejos", Icons.Default.TipsAndUpdates)
}

@Composable
fun HomeScreen() {
    Text(
        text = "¡Bienvenido a Guía Dragon City!\n\nPara principiantes 2026\n\nUsa la barra inferior para navegar",
        modifier = Modifier.fillMaxSize().padding(32.dp),
        style = MaterialTheme.typography.bodyLarge
    )
}


@Composable
fun DragonesScreen() {
    Text(
        text = "Dragones Básicos (próximamente)",
        modifier = Modifier.fillMaxSize().padding(32.dp)
    )
}

@Composable
fun CriaScreen() {
    Text(
        text = "Cría de Dragones (próximamente)",
        modifier = Modifier.fillMaxSize().padding(32.dp)
    )
}

@Composable
fun ConsejosScreen() {
    Text(
        text = "Consejos para Principiantes (próximamente)",
        modifier = Modifier.fillMaxSize().padding(32.dp)
    )
}