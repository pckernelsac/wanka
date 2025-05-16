/**
 * Controlador de grabación de audio para el Traductor Quechua Chanka
 */
document.addEventListener('DOMContentLoaded', function() {
    // Referencias a elementos del DOM
    const recordButton = document.getElementById('record-button');
    const stopButton = document.getElementById('stop-button');
    const audioPreview = document.getElementById('audio-preview');
    const audioPlayback = document.getElementById('audio-playback');
    const recorderStatus = document.getElementById('recorder-status');
    const form = document.getElementById('translation-form');
    
    // Variables para la grabación
    let mediaRecorder;
    let audioChunks = [];
    let audioBlob = null;
    
    // Configurar el botón de iniciar grabación
    recordButton.addEventListener('click', startRecording);
    
    // Configurar el botón de detener grabación
    stopButton.addEventListener('click', stopRecording);
    
    // Configurar el envío del formulario
    form.addEventListener('submit', submitForm);
    
    /**
     * Inicia la grabación de audio
     */
    function startRecording() {
        // Resetear cualquier grabación previa
        audioChunks = [];
        audioBlob = null;
        audioPreview.classList.add('hidden');
        
        // Solicitar permisos para acceder al micrófono
        navigator.mediaDevices.getUserMedia({ audio: true })
            .then(stream => {
                // Mostrar estado de grabación
                recorderStatus.innerHTML = `
                    <div class="text-red-600 font-medium">
                        <i class="fas fa-circle recording pulse"></i> Grabando...
                    </div>
                    <p class="text-sm text-gray-600 mt-1">Habla claramente cerca del micrófono</p>
                `;
                
                // Cambiar estilos de los botones
                recordButton.disabled = true;
                recordButton.classList.add('opacity-50', 'cursor-not-allowed');
                recordButton.classList.remove('hover:bg-red-700');
                
                stopButton.disabled = false;
                stopButton.classList.remove('bg-gray-400', 'opacity-50', 'cursor-not-allowed');
                stopButton.classList.add('bg-gray-800', 'hover:bg-gray-900');
                
                // Configurar el MediaRecorder
                mediaRecorder = new MediaRecorder(stream);
                
                mediaRecorder.ondataavailable = event => {
                    if (event.data.size > 0) {
                        audioChunks.push(event.data);
                    }
                };
                
                mediaRecorder.onstop = () => {
                    // Crear el blob de audio y mostrar la vista previa
                    audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                    const audioUrl = URL.createObjectURL(audioBlob);
                    audioPlayback.src = audioUrl;
                    audioPreview.classList.remove('hidden');
                    
                    // Detener todas las pistas de audio
                    stream.getTracks().forEach(track => track.stop());
                };
                
                // Iniciar grabación
                mediaRecorder.start();
            })
            .catch(error => {
                console.error('Error al acceder al micrófono:', error);
                showStatusMessage('error', 'No se pudo acceder al micrófono. Por favor, revisa los permisos del navegador.');
            });
    }
    
    /**
     * Detiene la grabación de audio
     */
    function stopRecording() {
        if (mediaRecorder && mediaRecorder.state !== 'inactive') {
            mediaRecorder.stop();
            
            // Actualizar estado
            recorderStatus.innerHTML = `
                <div class="text-green-600 font-medium">
                    <i class="fas fa-check-circle"></i> Grabación completada
                </div>
                <p class="text-sm text-gray-600 mt-1">Escucha la vista previa o vuelve a grabar</p>
            `;
            
            // Restablecer botones
            recordButton.disabled = false;
            recordButton.classList.remove('opacity-50', 'cursor-not-allowed');
            recordButton.classList.add('hover:bg-red-700');
            
            stopButton.disabled = true;
            stopButton.classList.add('bg-gray-400', 'opacity-50', 'cursor-not-allowed');
            stopButton.classList.remove('bg-gray-800', 'hover:bg-gray-900');
        }
    }
    
    /**
     * Envía el formulario de traducción
     */
    function submitForm(event) {
        event.preventDefault();
        
        const spanishWord = document.getElementById('spanish-word').value.trim();
        const quechuaWord = document.getElementById('quechua-word').value.trim();
        
        // Validar que se hayan completado todos los campos
        if (!spanishWord || !quechuaWord) {
            showStatusMessage('error', 'Por favor, completa todos los campos');
            return;
        }
        
        // Validar que se haya grabado audio
        if (!audioBlob) {
            showStatusMessage('error', 'Es necesario grabar la pronunciación en quechua');
            return;
        }
        
        // Crear FormData para enviar al servidor
        const formData = new FormData();
        formData.append('spanish_word', spanishWord);
        formData.append('quechua_word', quechuaWord);
        formData.append('audio', audioBlob, 'recording.webm');
        
        // Deshabilitar el botón de envío mientras se procesa
        const submitButton = document.getElementById('submit-button');
        submitButton.disabled = true;
        submitButton.innerHTML = '<i class="fas fa-circle-notch fa-spin mr-2"></i> Guardando...';
        
        // Enviar al servidor
        fetch('/api/save-translation', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showStatusMessage('success', '¡Traducción guardada correctamente!');
                
                // Limpiar el formulario
                form.reset();
                audioPreview.classList.add('hidden');
                audioBlob = null;
                
                // Recargar la lista de traducciones recientes
                loadRecentTranslations();
            } else {
                showStatusMessage('error', data.error || 'Error al guardar la traducción');
            }
        })
        .catch(error => {
            console.error('Error al enviar la traducción:', error);
            showStatusMessage('error', 'Error de conexión. Intenta nuevamente más tarde.');
        })
        .finally(() => {
            // Restaurar el botón de envío
            submitButton.disabled = false;
            submitButton.innerHTML = '<i class="fas fa-save mr-2"></i> Guardar traducción';
        });
    }
});