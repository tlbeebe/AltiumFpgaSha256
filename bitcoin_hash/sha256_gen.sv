module sha256_gen #(parameter integer NUM_OF_WORDS = 16) ( 
	input  logic        clk, reset_n, state,
	output logic        done,
	output logic [31:0] hash_out[0:7],
	output logic [15:0] memory_addr,
	input  logic [31:0] mem_read_data[0:7]);

// FSM state variables 
enum logic [2:0] {IDLE, BLOCK, COMPUTE, WRITE, FIN} state;

// Local variables
logic [31:0] w[64];
logic [31:0] h[8];
logic [31:0] A, B, C, D, E, F, G, H;
logic [31:0] writeCounter;
logic [31:0] compute_idx
logic [2:0] first_hash;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
}; 

// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
	$display("w: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h", w, a, b, c, d, e, f, g, h);

    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
	 
	 // Display the expanded words and other intermediate values
    //$display("t: %0d, w: %h, S1: %h, ch: %h, t1: %h, S0: %h, maj: %h, t2: %h", t, w, S1, ch, t1, S0, maj, t2);

    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// right rotation
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [7:0] r);
begin
    rightrotate = (x >> r) | (x << (32-r));
end
endfunction

// word expansion
function logic [31:0] wtnew; //function with no inputs
	logic [31:0] s0, s1;
	s0 = rightrotate(w[1],7) ^ rightrotate(w[1],18) ^ (w[1] >> 3);
	s1 = rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10);
	wtnew = w[0] + s0 + w[9] + s1;
endfunction

always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin 
	writeCounter <= 0; 
	first_hash <= 0;
    state <= IDLE;
  end 
  else case (state)
	IDLE: begin 
        if (start) begin  
		state <= BLOCK;
	end

    BLOCK: begin
		if (first_hash == 0) begin
                    	h[0] <= 32'h6a09e667;
                    	h[1] <= 32'hbb67ae85;
                    	h[2] <= 32'h3c6ef372;
                    	h[3] <= 32'ha54ff53a;
                    	h[4] <= 32'h510e527f;
                    	h[5] <= 32'h9b05688c;
                    	h[6] <= 32'h1f83d9ab;
                   	h[7] <= 32'h5be0cd19;
			A <= h[0];		
			B <= h[1];	
			C <= h[2];	
			D <= h[3];	
			E <= h[4];	
			F <= h[5];	
			G <= h[6];	
			H <= h[7];
			first_hash <= 1;
			writeCounter <= 1;
		end
		if (writeCounter < NUM_OF_WORDS)			
			state <= COMPUTE;
		end
		else begin 
			state <= WRITE;
		end	
	end
	
    COMPUTE: begin 
		if (compute_idx < 64) begin
			if (compute_idx < 16) begin
				$display("compute_idx: %d, Wt: %h", compute_idx, w[compute_idx]);
				for (int i = 0; i < 16; i++) begin
					w[i] <= mem_read_data[i];
				end
			end
			if (compute_idx >= 16) begin
				// Zeroize the words from index 16 to 63 before expansion
				w[compute_idx] <= 32'd0;
				// Perform lowercase sigma0 using rightrotate function
				s0 = rightrotate(w[compute_idx-15], 7) ^ rightrotate(w[compute_idx-15], 18) ^ (w[compute_idx-15] >> 3);
				// Perform lowercase sigma1 using rightrotate function
				s1 = rightrotate(w[compute_idx-2], 17) ^ rightrotate(w[compute_idx-2], 19) ^ (w[compute_idx-2] >> 10);
				// Expand the message schedule
				w[compute_idx] <= w[compute_idx-16] + s0 + w[compute_idx-7] + s1;
								
			end
			compute_idx <= compute_idx + 1;
		end
		
		else begin
			h[0] <= h[0] + A;
			h[1] <= h[1] + B;
			h[2] <= h[2] + C;
			h[3] <= h[3] + D;
			h[4] <= h[4] + E;
			h[5] <= h[5] + F;
			h[6] <= h[6] + G;
			h[7] <= h[7] + H
			state <= BLOCK;
		end
    end
	
    WRITE: begin
		for (int i = 0; i < 8; i++) begin
			hash_out[i] = h[i];
		end
		state <= FIN;
    end
  
	endcase
 end
 
//Finished when SHA256 complete, move to FIN AKA done
	FIN: begin
		assign done = (state == FIN);
	end
endmodule
