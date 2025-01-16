module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] header_addr, hash_out_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] memory_addr,
                    output logic [31:0] memory_write_data,
                     input logic [31:0] memory_read_data);

parameter num_nonces = 16;

enum logic [2:0] {IDLE, READ, COMPUTE, WRITE} state,next_state;
//logic [ 4:0] state; //Not sure about intializing state like this
logic [31:0] hash_out[num_nonces];
logic [31:0] message[32]; //Stores the message blocks
logic [31:0] hash[8][num_nonces]; // Hash values
logic [31:0] s1, s0;
logic [31:0] w[64];
logic [31:0] A, B, C, D, E, F, G, H; // Working variables

integer readCounter;
logic begin;

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// Student to add rest of the code here

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

//instantiate sha256 modules
genvar q;
generate
    for (q = 0; q < NUM_NONCES; q++) begin : generate_sha256_blocks
    sha256_gen block (
        .clk(clk),
        .reset_n(reset_n),
        .state(begin),
        .done(done),
        .mem_read_data(hash_out[q]),
        .mem_write_data(message[q])
        );
    end
endgenerate

always_ff @(posedge clk or negedge reset_n) begin
    if (!reset_n) begin

        // Reset working variables and FSM state
        {A, B, C, D, E, F, G, H} <= 256'd0;
        state <= IDLE;

        // Reset other control and data signals
        memory_write_data <= 0;
        memory_addr <= 0;
        memory_read_data <= 0;
        done <= 0;
    end 
    else begin

        // Sequential logic for FSM states
        //We'll probably need to change the CASE statements, as we need different approaches depending on which block we're looking at, plus the 3 "phases"

        case (state)
            IDLE: begin
                // Reset done signal and other control signals
                done <= 1'b0;
                mem_we <= 1'b0;
                mem_addr <= 16'd0;
                memory_write_data <= 32'd0;
                internal_message_addr <= message_addr;

                // Check if start signal is asserted
                if (start) begin
                    // Initialize or reset variables for a new SHA256 computation
                    // Reset hash values to initial SHA256 constants
                    for (i = 0; i < num_nonces; i++)
                        hash[i][0] <= 32'h6a09e667;
                        hash[i][0] <= 32'hbb67ae85;
                        hash[i][0] <= 32'h3c6ef372;
                        hash[i][0] <= 32'ha54ff53a;
                        hash[i][0] <= 32'h510e527f;
                        hash[i][0] <= 32'h9b05688c;
                        hash[i][0] <= 32'h1f83d9ab;
                        hash[i][0] <= 32'h5be0cd19;
                    end

                    // Reset other variables as needed
                    {A, B, C, D, E, F, G, H} <= 256'd0;
                    {readCounter, writeCounter, offset, present_addr, present_write_data, tstep} <= 0;
                    data_read <= 0;
    
                    // Transition to the next state to start processing
                    next_state <= READ;
                end else begin
                    // Stay in IDLE state
                    next_state <= IDLE;
                end
            end

            //Only 2 blocks needed
            READ: begin
                if (readCounter < 20) begin
                    //Reading the header
                    message[readCounter] <= mem_read_data;

                    // Increment the internal memory address for the next read
                    internal_message_addr <= internal_message_addr + 1;

                    // Increment the read counter
                    readCounter <= readCounter + 1;
                end 

                else begin
                    //Final space has one 32'h80000000 and 10 32'h00000000
                    message[20] <= 32'h80000000
                    readCounter <= readCounter + 1;
                    //Fill the next 10 with 0's
                    if (readCounter <= 30) begin
                        for(int i = 0; i<num_nonces; i++) begin
                        message[readCounter] <= 32'h00000000
                        readCounter <= readCounter + 1;
                    end
                end
                    //Append one 32'd640 
                    message[31] <= 32'd640;
                    readCounter <= 0;
                    next_state <= COMPUTE;
                end
            end

            //
            COMPUTE: begin

                //Apply generation statements math
                
                next_state <= WRITE;

            end

            WRITE: begin

                mem_we <= 1;
                memory_write_data <= output_addr;
                for (int i = 0; i<num_nonces; i++) begin
                   memory_write_data <= hash[0][i];
                end
                state <= IDLE;

            end

        endcase


endmodule
