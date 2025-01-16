module simplified_sha256 #(parameter integer NUM_OF_WORDS = 40)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [31:0] mem_addr,
 output logic [31:0] memory_write_data,
 input logic [31:0] mem_read_data
);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE} state;

parameter integer SIZE = NUM_OF_WORDS*32; 
localparam integer NUM_BLOCKS = determine_num_blocks(SIZE);

// Local variables
logic [31:0] w[16]; // Message schedule array
logic [31:0] message[100]; // Holds all the words to be hashed
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7; // Hash values
logic [31:0] A, B, C, D, E, F, G, H; // Working variables
logic [ 31:0] writeCounter; // Loop counters
logic [31:0] internal_message_addr;
logic [31:0] compute_idx;
logic [ 7:0] num_blocks;
logic [7:0] blockCounter; // Block counter
integer readCounter;
logic [31:0] s0, s1, wt;

// SHA256 K constants
// Using localparam instead of parameter because localparam ensures that the values remain constant and cannot be changed during instantiation, reflecting their role as fixed constants in the SHA-256 algorithm.
localparam int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

assign mem_clk = clk;

function automatic void wtnew(inout logic [31:0] w[16], input logic [31:0] new_wt);
    // Shift the elements of w down by one position
    for (int i = 0; i < 15; i++) begin
        w[i] = w[i + 1];
    end

    // Add the new wt value to the end of the array
    w[15] = new_wt;
endfunction


function automatic integer determine_num_blocks(input integer size);
    integer whole_part;
    whole_part = size / 512;

    if ((size % 512 >= 1) && (size % 512 <= 447)) begin
        return whole_part + 1;
    end else if ((size % 512 >= 448) && (size % 512 <= 511)) begin
        return whole_part + 2;
    end else begin
        // Handle the case where size is exactly a multiple of 512
        return whole_part + 1;
    end
endfunction

// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin

    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
	
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
																																																																							
    always_ff @(posedge clk, negedge reset_n) begin
		if (!reset_n) begin
			// Reset logic
			// Reset hash values to initial SHA256 constants
			h0 <= 32'h6a09e667;
			h1 <= 32'hbb67ae85;
			h2 <= 32'h3c6ef372;
			h3 <= 32'ha54ff53a;
			h4 <= 32'h510e527f;
			h5 <= 32'h9b05688c;
			h6 <= 32'h1f83d9ab;
			h7 <= 32'h5be0cd19;
			// Reset working variables and FSM state
			{A, B, C, D, E, F, G, H} <= 256'd0;
			state <= IDLE;
			A <= 32'h6a09e667;
			B <= 32'hbb67ae85;
			C <= 32'h3c6ef372;
			D <= 32'ha54ff53a;
			E <= 32'h510e527f;
			F <= 32'h9b05688c;
			G <= 32'h1f83d9ab;
			H <= 32'h5be0cd19;

			// Reset other control and data signals
			readCounter <= -2;
			writeCounter <= 0;
			compute_idx <= 0;
			mem_addr <= 0;
			mem_we <= 0;
			done <= 0;
			blockCounter <= 0;
		end else begin
			// Sequential logic for FSM states
			case (state)
				IDLE: begin
					// Reset and initialization for each block
					if (blockCounter < NUM_BLOCKS) begin
						// Reset done signal and other control signals
						done <= 1'b0;
						mem_we <= 1'b0;
						mem_addr <= 32'd0;
						memory_write_data <= 32'd0;
						internal_message_addr <= message_addr;

						// Check if start signal is asserted
						if (start) begin
							// Initialize or reset variables for a new SHA256 computation
							// Reset hash values to initial SHA256 constants
							h0 <= 32'h6a09e667;
							h1 <= 32'hbb67ae85;
							h2 <= 32'h3c6ef372;
							h3 <= 32'ha54ff53a;
							h4 <= 32'h510e527f;
							h5 <= 32'h9b05688c;
							h6 <= 32'h1f83d9ab;
							h7 <= 32'h5be0cd19;

							// Reset other variables as needed
							readCounter <= -2;
							writeCounter <= 0;
							compute_idx <= 0;
    
							// Transition to the next state to start processing
							state <= READ;
							end else begin
							// Stay in IDLE state
							state <= IDLE;
						end
					end else begin
						// Completed processing all blocks
						done <= 1'b1;
						state <= READ;
					end
				end
		
			READ: begin
				if (readCounter < NUM_OF_WORDS) begin
					mem_addr <= internal_message_addr;		
					if (readCounter >= 0) begin
						message[readCounter] <= mem_read_data; // Read data into message block
					end
					readCounter <= readCounter + 1; // Increment read counter
					internal_message_addr <= internal_message_addr + 1;
				end else if (readCounter == NUM_OF_WORDS) begin
					// Add '1' bit at the end of the message
					message[readCounter] <= 32'h80000000;
					readCounter <= readCounter + 1;
					if (readCounter%16 == 14) begin
						for (int n = 15; n < (NUM_OF_WORDS+17); n++) begin
							message[n+16] <= 32'h00000000;
						end
						readCounter <= readCounter + 17;
					end 
				end else if ((readCounter % 16) < 15) begin
					// Fill with '0' bits until we reach the length field. Only using the last word for the length field.
					message[readCounter] <= 32'h00000000;
					readCounter <= readCounter + 1;
				end else if ((readCounter % 16) == 15) begin
					// Second word of the length field lower 32 bits
					message[readCounter] <= (SIZE);
					readCounter <= 0; // Reset read counter
					state <= BLOCK; // Transition to BLOCK state
				end
			end
		

			BLOCK: begin
				for (int n = 0; n < 16; n++) begin
					w[n] <= message[n + blockCounter*16];
				end
				state <= COMPUTE;
			end
			  
			COMPUTE: begin    
				if (compute_idx < 64) begin
					if (compute_idx == 0) begin
						A = h0;
						B = h1;
						C = h2;
						D = h3;
						E = h4;
						F = h5;
						G = h6;
						H = h7;
					end
					if (compute_idx < 16) begin
						{A, B, C, D, E, F, G, H} <= sha256_op(A, B, C, D, E, F, G, H, w[compute_idx], compute_idx);
						compute_idx <= compute_idx + 1;
							if (compute_idx == 15) begin
								// Perform lowercase sigma0 using rightrotate function
								s0 = rightrotate(w[1], 7) ^
									rightrotate(w[1], 18) ^
									(w[1] >> 3);

								// Perform lowercase sigma1 using rightrotate function
								s1 = rightrotate(w[14], 17) ^
									rightrotate(w[14], 19) ^
									(w[14] >> 10);

								// Expand the message schedule
								//wt <= w[0] + s0 + w[9] + s1;
								wtnew(w, w[0] + s0 + w[9] + s1);
							end
					end else if (compute_idx >= 16) begin
						// Perform lowercase sigma0 using rightrotate function
						s0 = rightrotate(w[1], 7) ^
							rightrotate(w[1], 18) ^
							(w[1] >> 3);

						// Perform lowercase sigma1 using rightrotate function
						s1 = rightrotate(w[14], 17) ^
							rightrotate(w[14], 19) ^
							(w[14] >> 10);

						{A, B, C, D, E, F, G, H} <= sha256_op(A, B, C, D, E, F, G, H, w[15], compute_idx);
						// Expand the message schedule
						wtnew(w, w[0] + s0 + w[9] + s1);
							
						compute_idx <= compute_idx + 1;
					end
				end else begin
					// Add the compressed chunk to the current hash value
					h0 <= h0 + A;
					h1 <= h1 + B;
					h2 <= h2 + C;
					h3 <= h3 + D;
					h4 <= h4 + E;
					h5 <= h5 + F;
					h6 <= h6 + G;
					h7 <= h7 + H;
	
					// Check if this is the last block
					if (blockCounter >= NUM_BLOCKS - 1) begin
						// Transition to WRITE to output the final hash
						state <= WRITE;
						memory_write_data <= h0;
					end else begin
						// Prepare to process the next block
						blockCounter <= blockCounter + 1;
						state <= BLOCK; // Loop back to process the next block
						// Reset indices for the next block processing
						compute_idx <= 0;
					end
				end
			end

			WRITE: begin
				if (writeCounter < 8) begin
					// Enable memory write
					mem_we <= 1'b1;
					// Set the memory address to write to
					mem_addr <= output_addr + writeCounter;
					// Write each hash value in sequence
					case (writeCounter)
						0: memory_write_data <= h0;
						1: memory_write_data <= h1;
						2: memory_write_data <= h2;
						3: memory_write_data <= h3;
						4: memory_write_data <= h4;
						5: memory_write_data <= h5;
						6: memory_write_data <= h6;
						7: memory_write_data <= h7;
					endcase

					// Increment the counter for the next cycle
					writeCounter <= writeCounter + 1;
				end else begin
					// Once all hash values are written, reset the counter and signal completion
					writeCounter <= 0;
					done <= 1'b1;
					mem_we <= 1'b0; // Disable memory write
					state <= IDLE; // Transition back to IDLE
				end
			end
		endcase
	end
end
endmodule