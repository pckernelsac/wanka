/**
 * Controlador de reproducción de audio para el Traductor Quechua Chanka
 */
document.addEventListener('DOMContentLoaded', function() {
    // Reproductor de audio global
    let currentAudio = null;
    let currentButton = null;

    // Configurar búsqueda con debounce
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        let debounceTimeout;
        
        searchInput.addEventListener('input', function() {
            clearTimeout(debounceTimeout);
            const query = this.value.trim();
            
            debounceTimeout = setTimeout(() => {
                if (query.length >= 2) {
                    searchTranslations(query);
                } else if (query.length === 0) {
                    hideResults();
                }
            }, 300);
        });
    }

    /**
     * Configura los botones para reproducir audio
     */
    window.setupAudioButtons = function() {
        document.querySelectorAll('.play-audio').forEach(button => {
            button.addEventListener('click', function() {
                const audioPath = this.getAttribute('data-audio');
                toggleAudioPlayback(audioPath, this);
            });
        });
    };

    /**
     * Buscar traducciones en la API
     * @param {string} query - Texto de búsqueda
     */
    window.searchTranslations = function(query) {
        if (query.length < 2) return;
        
        // Mostrar indicador de carga
        const resultsContainer = document.getElementById('results-container');
        if (resultsContainer) {
            resultsContainer.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-circle-notch fa-spin text-indigo-500 text-2xl"></i>
                    <p class="text-gray-600 mt-2">Buscando...</p>
                </div>
            `;
        }
        
        // Ocultar mensaje inicial
        const initialMessage = document.getElementById('initial-message');
        if (initialMessage) {
            initialMessage.classList.add('hidden');
        }
        
        // Mostrar sección de resultados
        const searchResults = document.getElementById('search-results');
        if (searchResults) {
            searchResults.classList.remove('hidden');
        }
        
        // Esconder mensaje de no resultados
        const noResults = document.getElementById('no-results');
        if (noResults) {
            noResults.classList.add('hidden');
        }
        
        // Realizar búsqueda
        fetch(`/api/search?q=${encodeURIComponent(query)}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Error HTTP: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (!Array.isArray(data)) {
                    if (data.error) {
                        throw new Error(data.error);
                    } else {
                        throw new Error('Formato de respuesta inválido');
                    }
                }
                
                if (data.length === 0) {
                    if (searchResults) searchResults.classList.add('hidden');
                    if (noResults) noResults.classList.remove('hidden');
                    return;
                }
                
                if (searchResults) searchResults.classList.remove('hidden');
                if (noResults) noResults.classList.add('hidden');
                
                if (resultsContainer) {
                    resultsContainer.innerHTML = '';
                    
                    data.forEach(item => {
                        const downloadButton = item.allow_download 
                            ? `<a href="/audio/${item.audio_path}" download class="text-emerald-600 hover:text-emerald-800 transition-colors ml-3">
                                 <i class="fas fa-download"></i>
                               </a>` 
                            : '';
                        
                        resultsContainer.innerHTML += `
                            <div class="bg-gray-50 rounded-lg p-5 mb-4 border border-gray-200">
                                <div class="flex justify-between items-start">
                                    <div>
                                        <h3 class="text-lg font-semibold text-gray-800">${item.spanish_word}</h3>
                                        <p class="text-emerald-600 font-medium mt-1">${item.quechua_word}</p>
                                        <p class="text-xs text-gray-500 mt-2">
                                            <i class="fas fa-user mr-1"></i> Traductor: ${item.translator || 'Anónimo'}
                                        </p>
                                    </div>
                                    <div>
                                        <button class="play-audio text-emerald-600 hover:text-emerald-800 transition-colors" 
                                            data-audio="/audio/${item.audio_path}">
                                            <i class="fas fa-play-circle text-2xl"></i>
                                        </button>
                                        ${downloadButton}
                                    </div>
                                </div>
                                <div class="mt-3">
                                    <audio src="/audio/${item.audio_path}" controls class="w-full"></audio>
                                </div>
                            </div>
                        `;
                    });
                    
                    // Configurar botones de reproducción
                    setupAudioButtons();
                }
            })
            .catch(error => {
                console.error('Error al buscar traducciones:', error);
                if (resultsContainer) {
                    resultsContainer.innerHTML = `
                        <div class="bg-red-50 text-red-800 p-4 rounded-lg border border-red-200">
                            <div class="flex">
                                <div class="flex-shrink-0">
                                    <i class="fas fa-exclamation-circle text-red-500"></i>
                                </div>
                                <div class="ml-3">
                                    <p class="text-sm font-medium">Error al buscar traducciones: ${error.message}</p>
                                </div>
                            </div>
                        </div>
                    `;
                }
            });
    };

    /**
     * Ocultar resultados y mostrar mensaje inicial
     */
    window.hideResults = function() {
        const searchResults = document.getElementById('search-results');
        const noResults = document.getElementById('no-results');
        const initialMessage = document.getElementById('initial-message');
        
        if (searchResults) searchResults.classList.add('hidden');
        if (noResults) noResults.classList.add('hidden');
        if (initialMessage) initialMessage.classList.remove('hidden');
    };

    /**
     * Cargar traducciones populares
     */
    window.loadPopularTranslations = function() {
        const container = document.getElementById('popular-translations');
        if (!container) return;
        
        // Mostrar indicador de carga
        container.innerHTML = `
            <div class="col-span-3 text-center py-4">
                <i class="fas fa-circle-notch fa-spin text-indigo-500 text-2xl"></i>
                <p class="text-gray-600 mt-2">Cargando traducciones populares...</p>
            </div>
        `;
        
        fetch('/api/translations')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Error HTTP: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (!Array.isArray(data)) {
                    if (data.error) {
                        throw new Error(data.error);
                    } else {
                        throw new Error('Formato de respuesta inválido');
                    }
                }
                
                container.innerHTML = '';
                
                if (data.length === 0) {
                    container.innerHTML = `
                        <div class="col-span-3 text-center py-4">
                            <p class="text-gray-500">No hay traducciones disponibles aún</p>
                        </div>
                    `;
                    return;
                }
                
                // Mostrar hasta 6 traducciones populares
                const popularData = data.slice(0, 6);
                
                popularData.forEach(item => {
                    const downloadButton = item.allow_download 
                        ? `<a href="/audio/${item.audio_path}" download class="text-emerald-600 hover:text-emerald-800 transition-colors ml-2">
                             <i class="fas fa-download text-sm"></i>
                           </a>` 
                        : '';
                    
                    container.innerHTML += `
                        <div class="p-4 border border-gray-200 rounded-lg hover:border-emerald-300 hover:shadow-sm transition-all">
                            <div class="flex justify-between items-start">
                                <div>
                                    <h3 class="font-medium text-gray-800">${item.spanish_word}</h3>
                                    <p class="text-sm text-emerald-600 mt-1">${item.quechua_word}</p>
                                </div>
                                <div class="flex">
                                    <button class="play-audio text-emerald-600 hover:text-emerald-800 transition-colors" 
                                        data-audio="/audio/${item.audio_path}">
                                        <i class="fas fa-play-circle text-xl"></i>
                                    </button>
                                    ${downloadButton}
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                // Configurar botones de reproducción
                setupAudioButtons();
            })
            .catch(error => {
                console.error('Error al cargar traducciones populares:', error);
                container.innerHTML = `
                    <div class="col-span-3 p-4 bg-red-50 text-red-800 rounded-lg border border-red-200">
                        <div class="flex">
                            <div class="flex-shrink-0">
                                <i class="fas fa-exclamation-circle text-red-500"></i>
                            </div>
                            <div class="ml-3">
                                <p class="text-sm font-medium">Error al cargar traducciones: ${error.message}</p>
                                <p class="text-xs mt-1">Intenta recargar la página</p>
                            </div>
                        </div>
                    </div>
                `;
            });
    };

    /**
     * Alterna la reproducción de audio
     * @param {string} audioPath - Ruta al archivo de audio
     * @param {HTMLElement} button - Botón de reproducción
     */
    function toggleAudioPlayback(audioPath, button) {
        const icon = button.querySelector('i');
        
        // Si hay un audio reproduciéndose, lo detenemos
        if (currentAudio && currentAudio.src.includes(audioPath)) {
            if (currentAudio.paused) {
                currentAudio.play();
                icon.classList.remove('fa-play-circle');
                icon.classList.add('fa-pause-circle');
            } else {
                currentAudio.pause();
                icon.classList.remove('fa-pause-circle');
                icon.classList.add('fa-play-circle');
            }
            return;
        }
        
        // Si había otro audio reproduciéndose, lo detenemos
        if (currentAudio && currentButton) {
            currentAudio.pause();
            const prevIcon = currentButton.querySelector('i');
            prevIcon.classList.remove('fa-pause-circle');
            prevIcon.classList.add('fa-play-circle');
        }
        
        // Crear nuevo audio
        currentAudio = new Audio(audioPath);
        currentButton = button;
        
        // Manejar errores de carga de audio
        currentAudio.onerror = function() {
            icon.classList.remove('fa-pause-circle', 'fa-spin');
            icon.classList.add('fa-exclamation-circle');
            setTimeout(() => {
                icon.classList.remove('fa-exclamation-circle');
                icon.classList.add('fa-play-circle');
            }, 2000);
        };
        
        // Configurar eventos
        currentAudio.onplay = function() {
            icon.classList.remove('fa-play-circle', 'fa-spin');
            icon.classList.add('fa-pause-circle');
        };
        
        currentAudio.onpause = currentAudio.onended = function() {
            icon.classList.remove('fa-pause-circle', 'fa-spin');
            icon.classList.add('fa-play-circle');
        };
        
        // Mostrar cargando
        icon.classList.remove('fa-play-circle');
        icon.classList.add('fa-circle-notch', 'fa-spin');
        
        // Reproducir
        currentAudio.play().catch(error => {
            console.error('Error al reproducir audio:', error);
            icon.classList.remove('fa-circle-notch', 'fa-spin');
            icon.classList.add('fa-exclamation-circle');
            setTimeout(() => {
                icon.classList.remove('fa-exclamation-circle');
                icon.classList.add('fa-play-circle');
            }, 2000);
        });
    }

    // Inicializar botones de audio existentes y cargar traducciones populares
    if (document.getElementById('popular-translations')) {
        loadPopularTranslations();
    } else {
        setupAudioButtons();
    }
});

/**
 * Manejo de favoritos para traducciones
 */
const favoriteManager = {
    /**
     * Guarda una traducción en favoritos
     * @param {number} translationId - ID de la traducción
     */
    addFavorite: function(translationId) {
        const favorites = this.getFavorites();
        if (!favorites.includes(translationId)) {
            favorites.push(translationId);
            this.saveFavorites(favorites);
        }
    },
    
    /**
     * Elimina una traducción de favoritos
     * @param {number} translationId - ID de la traducción
     */
    removeFavorite: function(translationId) {
        const favorites = this.getFavorites();
        const index = favorites.indexOf(translationId);
        if (index !== -1) {
            favorites.splice(index, 1);
            this.saveFavorites(favorites);
        }
    },
    
    /**
     * Verifica si una traducción está en favoritos
     * @param {number} translationId - ID de la traducción
     * @returns {boolean}
     */
    isFavorite: function(translationId) {
        return this.getFavorites().includes(translationId);
    },
    
    /**
     * Obtiene la lista de favoritos
     * @returns {Array}
     */
    getFavorites: function() {
        const favorites = localStorage.getItem('quechua-favorites');
        return favorites ? JSON.parse(favorites) : [];
    },
    
    /**
     * Guarda la lista de favoritos
     * @param {Array} favorites - Lista de IDs de traducciones favoritas
     */
    saveFavorites: function(favorites) {
        localStorage.setItem('quechua-favorites', JSON.stringify(favorites));
    }
};

/**
 * Historial de búsquedas recientes
 */
const searchHistoryManager = {
    /**
     * Añade un término de búsqueda al historial
     * @param {string} term - Término de búsqueda
     */
    addSearchTerm: function(term) {
        const history = this.getSearchHistory();
        
        // Evitar duplicados
        const index = history.indexOf(term);
        if (index !== -1) {
            history.splice(index, 1);
        }
        
        // Añadir al principio
        history.unshift(term);
        
        // Limitar a 10 términos
        if (history.length > 10) {
            history.pop();
        }
        
        this.saveSearchHistory(history);
    },
    
    /**
     * Obtiene el historial de búsqueda
     * @returns {Array}
     */
    getSearchHistory: function() {
        const history = localStorage.getItem('quechua-search-history');
        return history ? JSON.parse(history) : [];
    },
    
    /**
     * Guarda el historial de búsqueda
     * @param {Array} history - Lista de términos de búsqueda
     */
    saveSearchHistory: function(history) {
        localStorage.setItem('quechua-search-history', JSON.stringify(history));
    },
    
    /**
     * Limpia el historial de búsqueda
     */
    clearHistory: function() {
        localStorage.removeItem('quechua-search-history');
    }
};