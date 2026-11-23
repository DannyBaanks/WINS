#version 420 core
layout(binding = 0) uniform sampler2D ptex0;
layout(location = 1) in vec4 vi1;
layout(location = 0) out vec4 vo0;
layout(location = 1) out vec4 vo1;
// Synthetic clean MRT shader: declares BOTH SV_Target0 and SV_Target1 explicitly.
void main() {
    vo0 = texture(ptex0, vi1.xy);
    vo1 = vec4(0.0);
}
